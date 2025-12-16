package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/hkdf"
)

const (
	// EntropyBytes128 is 128 bits (16 bytes), yielding a 12-word BIP39 mnemonic.
	EntropyBytes128 = 16

	activeKeySalt   = "safeauth-ed25519-v1"
	recoveryKeySalt = "safeauth-recovery-v1"
	loginDomainTag  = "safeauth-login-v1"
	rotateDomainTag = "safeauth-rotate-v1"
)

// ServiceKeypair holds the derived per-origin Ed25519 signing keypair,
// the root-derived recovery keypair for rotation, and the stable per-origin account ID.
type ServiceKeypair struct {
	Origin          string
	AccountIndex    uint32
	Epoch           uint32
	AccountID       string
	PublicKey       ed25519.PublicKey
	PrivateKey      ed25519.PrivateKey
	RecoveryPubKey  ed25519.PublicKey
	RecoveryPrivKey ed25519.PrivateKey
}

// Wipe zeroes out private key material held in memory.
func (k *ServiceKeypair) Wipe() {
	if k == nil {
		return
	}
	ZeroBytes(k.PrivateKey)
	ZeroBytes(k.RecoveryPrivKey)
}

// ZeroBytes overwrites a byte slice with zeros.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// GenerateMnemonic128 generates 128 bits of cryptographic randomness from crypto/rand
// and encodes it as a 12-word BIP39 mnemonic phrase.
func GenerateMnemonic128() (string, error) {
	entropy := make([]byte, EntropyBytes128)
	defer ZeroBytes(entropy)

	if _, err := io.ReadFull(rand.Reader, entropy); err != nil {
		return "", fmt.Errorf("failed to read cryptographic entropy: %w", err)
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", fmt.Errorf("failed to encode BIP39 mnemonic: %w", err)
	}
	return mnemonic, nil
}

// ValidateMnemonic checks that a mnemonic is a valid BIP39 phrase with a valid checksum.
func ValidateMnemonic(mnemonic string) bool {
	return bip39.IsMnemonicValid(strings.TrimSpace(mnemonic))
}

// MasterSeedFromMnemonic derives the 64-byte BIP39 master seed from a 12-word mnemonic
// and an optional passphrase.
func MasterSeedFromMnemonic(mnemonic, passphrase string) ([]byte, error) {
	normalized := strings.Join(strings.Fields(strings.TrimSpace(mnemonic)), " ")
	if !bip39.IsMnemonicValid(normalized) {
		return nil, errors.New("invalid BIP39 mnemonic phrase")
	}
	return bip39.NewSeed(normalized, passphrase), nil
}

// CanonicalOrigin normalizes a service origin (e.g. "https://Auth.Example.com:8443/")
// into a canonical lowercase host[:port] identifier so keys are bound consistently.
func CanonicalOrigin(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", errors.New("origin cannot be empty")
	}
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil {
			return "", fmt.Errorf("invalid origin URL: %w", err)
		}
		if u.Host == "" {
			return "", errors.New("origin URL missing host")
		}
		return strings.ToLower(u.Host), nil
	}
	s = strings.TrimRight(s, "/")
	if s == "" || strings.ContainsAny(s, " \t\n\r") {
		return "", errors.New("invalid origin")
	}
	return strings.ToLower(s), nil
}

// DeriveServiceKeys deterministically derives an unlinkable Ed25519 keypair and recovery keypair
// for a specific service origin, account index, and key rotation epoch using HKDF-SHA256.
func DeriveServiceKeys(masterSeed []byte, rawOrigin string, accountIndex, epoch uint32) (*ServiceKeypair, error) {
	if len(masterSeed) < 16 {
		return nil, errors.New("master seed too short")
	}
	origin, err := CanonicalOrigin(rawOrigin)
	if err != nil {
		return nil, err
	}

	// Derive active Ed25519 keypair bound to (origin, accountIndex, epoch).
	activeInfo := make([]byte, 0, len(origin)+32)
	activeInfo = append(activeInfo, []byte("origin:")...)
	activeInfo = append(activeInfo, []byte(origin)...)
	activeInfo = append(activeInfo, '|')
	var idxBuf [4]byte
	binary.BigEndian.PutUint32(idxBuf[:], accountIndex)
	activeInfo = append(activeInfo, idxBuf[:]...)
	activeInfo = append(activeInfo, '|')
	var epochBuf [4]byte
	binary.BigEndian.PutUint32(epochBuf[:], epoch)
	activeInfo = append(activeInfo, epochBuf[:]...)

	activeSeed := make([]byte, ed25519.SeedSize)
	defer ZeroBytes(activeSeed)
	rActive := hkdf.New(sha256.New, masterSeed, []byte(activeKeySalt), activeInfo)
	if _, err := io.ReadFull(rActive, activeSeed); err != nil {
		return nil, fmt.Errorf("hkdf active key derivation failed: %w", err)
	}
	priv := ed25519.NewKeyFromSeed(activeSeed)
	pub := priv.Public().(ed25519.PublicKey)

	// Derive recovery Ed25519 keypair bound to (origin, accountIndex), independent of epoch.
	recInfo := make([]byte, 0, len(origin)+16)
	recInfo = append(recInfo, []byte("recovery:")...)
	recInfo = append(recInfo, []byte(origin)...)
	recInfo = append(recInfo, '|')
	recInfo = append(recInfo, idxBuf[:]...)

	recSeed := make([]byte, ed25519.SeedSize)
	defer ZeroBytes(recSeed)
	rRec := hkdf.New(sha256.New, masterSeed, []byte(recoveryKeySalt), recInfo)
	if _, err := io.ReadFull(rRec, recSeed); err != nil {
		return nil, fmt.Errorf("hkdf recovery key derivation failed: %w", err)
	}
	recPriv := ed25519.NewKeyFromSeed(recSeed)
	recPub := recPriv.Public().(ed25519.PublicKey)

	// Derive stable, origin-isolated AccountID from recoveryPub + origin so it survives rotations
	// and cannot be correlated across different origins.
	h := sha256.New()
	h.Write([]byte("safeauth-account-id-v1|"))
	h.Write([]byte(origin))
	h.Write([]byte("|"))
	h.Write(recPub)
	acctDigest := h.Sum(nil)
	accountID := hex.EncodeToString(acctDigest[:16])

	return &ServiceKeypair{
		Origin:          origin,
		AccountIndex:    accountIndex,
		Epoch:           epoch,
		AccountID:       accountID,
		PublicKey:       pub,
		PrivateKey:      priv,
		RecoveryPubKey:  recPub,
		RecoveryPrivKey: recPriv,
	}, nil
}

// LoginPayload constructs the canonical domain-separated message signed during login.
func LoginPayload(origin, accountID, nonceB64 string, timestamp int64) []byte {
	return []byte(fmt.Sprintf("%s\n%s\n%s\n%s\n%d", loginDomainTag, origin, accountID, nonceB64, timestamp))
}

// SignLoginChallenge signs a login challenge using the derived Ed25519 private key.
func SignLoginChallenge(priv ed25519.PrivateKey, origin, accountID, nonceB64 string, timestamp int64) []byte {
	msg := LoginPayload(origin, accountID, nonceB64, timestamp)
	return ed25519.Sign(priv, msg)
}

// VerifyLoginChallenge verifies an Ed25519 login signature against the canonical payload.
func VerifyLoginChallenge(pub ed25519.PublicKey, origin, accountID, nonceB64 string, timestamp int64, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	msg := LoginPayload(origin, accountID, nonceB64, timestamp)
	return ed25519.Verify(pub, msg, sig)
}

// RotatePayload constructs the canonical domain-separated message signed by the recovery key
// to promote a new active public key for an account.
func RotatePayload(origin, accountID, newPubB64, nonceB64 string, timestamp int64) []byte {
	return []byte(fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%d", rotateDomainTag, origin, accountID, newPubB64, nonceB64, timestamp))
}

// SignRotateChallenge signs a key-rotation request using the root-derived recovery private key.
func SignRotateChallenge(recoveryPriv ed25519.PrivateKey, origin, accountID string, newPub ed25519.PublicKey, nonceB64 string, timestamp int64) []byte {
	newPubB64 := base64.StdEncoding.EncodeToString(newPub)
	msg := RotatePayload(origin, accountID, newPubB64, nonceB64, timestamp)
	return ed25519.Sign(recoveryPriv, msg)
}

// VerifyRotateChallenge verifies a key-rotation signature against the stored recovery public key.
func VerifyRotateChallenge(recoveryPub ed25519.PublicKey, origin, accountID string, newPub ed25519.PublicKey, nonceB64 string, timestamp int64, sig []byte) bool {
	if len(recoveryPub) != ed25519.PublicKeySize || len(newPub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	newPubB64 := base64.StdEncoding.EncodeToString(newPub)
	msg := RotatePayload(origin, accountID, newPubB64, nonceB64, timestamp)
	return ed25519.Verify(recoveryPub, msg, sig)
}
