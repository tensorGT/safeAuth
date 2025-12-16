package identity

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestMnemonicGenerationAndMasterSeed(t *testing.T) {
	m1, err := GenerateMnemonic128()
	if err != nil {
		t.Fatalf("GenerateMnemonic128 failed: %v", err)
	}
	words := strings.Fields(m1)
	if len(words) != 12 {
		t.Fatalf("expected 12 words for 128-bit entropy, got %d", len(words))
	}
	if !ValidateMnemonic(m1) {
		t.Fatalf("generated mnemonic failed validation")
	}

	m2, err := GenerateMnemonic128()
	if err != nil {
		t.Fatalf("second GenerateMnemonic128 failed: %v", err)
	}
	if m1 == m2 {
		t.Fatalf("two generated mnemonics unexpectedly matched")
	}

	seed1, err := MasterSeedFromMnemonic(m1, "")
	if err != nil {
		t.Fatalf("MasterSeedFromMnemonic failed: %v", err)
	}
	seed2, err := MasterSeedFromMnemonic(m1, "")
	if err != nil {
		t.Fatalf("MasterSeedFromMnemonic repeat failed: %v", err)
	}
	if !bytes.Equal(seed1, seed2) {
		t.Fatalf("master seed derivation is not deterministic")
	}

	if _, err := MasterSeedFromMnemonic("invalid word list here", ""); err == nil {
		t.Fatalf("expected error for invalid mnemonic")
	}
}

func TestPerOriginKeyIsolationAndDeterminism(t *testing.T) {
	mnemonic, err := GenerateMnemonic128()
	if err != nil {
		t.Fatalf("GenerateMnemonic128: %v", err)
	}
	seed, err := MasterSeedFromMnemonic(mnemonic, "")
	if err != nil {
		t.Fatalf("MasterSeedFromMnemonic: %v", err)
	}

	kA1, err := DeriveServiceKeys(seed, "https://Auth.Example.com/", 0, 0)
	if err != nil {
		t.Fatalf("DeriveServiceKeys A1: %v", err)
	}
	kA2, err := DeriveServiceKeys(seed, "auth.example.com", 0, 0)
	if err != nil {
		t.Fatalf("DeriveServiceKeys A2: %v", err)
	}
	if !bytes.Equal(kA1.PublicKey, kA2.PublicKey) || kA1.AccountID != kA2.AccountID {
		t.Fatalf("canonical origin derivation is not deterministic")
	}

	// Different origin must yield completely distinct, unlinkable keys and account ID.
	kB, err := DeriveServiceKeys(seed, "api.other-service.org", 0, 0)
	if err != nil {
		t.Fatalf("DeriveServiceKeys B: %v", err)
	}
	if bytes.Equal(kA1.PublicKey, kB.PublicKey) {
		t.Fatalf("different origins produced identical public keys")
	}
	if bytes.Equal(kA1.RecoveryPubKey, kB.RecoveryPubKey) {
		t.Fatalf("different origins produced identical recovery public keys")
	}
	if kA1.AccountID == kB.AccountID {
		t.Fatalf("different origins produced identical account IDs")
	}

	// Different epoch must rotate active key while preserving AccountID and RecoveryPubKey.
	kAEpoch1, err := DeriveServiceKeys(seed, "auth.example.com", 0, 1)
	if err != nil {
		t.Fatalf("DeriveServiceKeys A epoch 1: %v", err)
	}
	if bytes.Equal(kA1.PublicKey, kAEpoch1.PublicKey) {
		t.Fatalf("new epoch did not change active public key")
	}
	if kA1.AccountID != kAEpoch1.AccountID || !bytes.Equal(kA1.RecoveryPubKey, kAEpoch1.RecoveryPubKey) {
		t.Fatalf("rotation changed stable AccountID or RecoveryPubKey")
	}
}

func TestSignAndVerifyChallenge(t *testing.T) {
	mnemonic, _ := GenerateMnemonic128()
	seed, _ := MasterSeedFromMnemonic(mnemonic, "")
	k0, _ := DeriveServiceKeys(seed, "auth.example.com", 0, 0)
	k1, _ := DeriveServiceKeys(seed, "auth.example.com", 0, 1)

	nonce := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	ts := time.Now().Unix()

	sig := SignLoginChallenge(k0.PrivateKey, k0.Origin, k0.AccountID, nonce, ts)
	if !VerifyLoginChallenge(k0.PublicKey, k0.Origin, k0.AccountID, nonce, ts, sig) {
		t.Fatalf("valid login signature rejected")
	}
	if VerifyLoginChallenge(k0.PublicKey, "evil.example.com", k0.AccountID, nonce, ts, sig) {
		t.Fatalf("signature verified for wrong origin")
	}
	if VerifyLoginChallenge(k1.PublicKey, k0.Origin, k0.AccountID, nonce, ts, sig) {
		t.Fatalf("signature verified for wrong key")
	}

	rotSig := SignRotateChallenge(k0.RecoveryPrivKey, k0.Origin, k0.AccountID, k1.PublicKey, nonce, ts)
	if !VerifyRotateChallenge(k0.RecoveryPubKey, k0.Origin, k0.AccountID, k1.PublicKey, nonce, ts, rotSig) {
		t.Fatalf("valid rotation signature rejected")
	}
	if VerifyRotateChallenge(k0.PublicKey, k0.Origin, k0.AccountID, k1.PublicKey, nonce, ts, rotSig) {
		t.Fatalf("active key should not validate as recovery key")
	}
	var fakePub ed25519.PublicKey = make([]byte, ed25519.PublicKeySize)
	if VerifyRotateChallenge(k0.RecoveryPubKey, k0.Origin, k0.AccountID, fakePub, nonce, ts, rotSig) {
		t.Fatalf("rotation signature verified for different new public key")
	}
}
