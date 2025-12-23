package vault

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/safeauth/safeauth/internal/identity"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	vaultVersion = 1
	vaultAAD     = "safeauth-vault-v1"
	saltSize     = 16

	defaultArgonTime    uint32 = 3
	defaultArgonMemory  uint32 = 64 * 1024 // 64 MiB
	defaultArgonThreads uint8  = 4
)

// OriginState tracks the account index and current key rotation epoch for a service origin.
type OriginState struct {
	AccountIndex uint32 `json:"account_index"`
	Epoch        uint32 `json:"epoch"`
}

// VaultData is the plaintext payload encrypted inside the local vault file.
type VaultData struct {
	Mnemonic string                 `json:"mnemonic"`
	Origins  map[string]OriginState `json:"origins"`
	Sessions map[string]string      `json:"sessions,omitempty"`
}

type encryptedVaultFile struct {
	Version    int    `json:"version"`
	KDF        string `json:"kdf"`
	Salt       string `json:"salt"`
	Time       uint32 `json:"time"`
	MemoryKB   uint32 `json:"memory_kb"`
	Threads    uint8  `json:"threads"`
	Cipher     string `json:"cipher"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// DefaultVaultPath returns ~/.safeauth/vault.json.
func DefaultVaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	return filepath.Join(home, ".safeauth", "vault.json"), nil
}

// SaveVault encrypts data with Argon2id + XChaCha20-Poly1305 and writes it atomically with 0600 permissions.
func SaveVault(path, passphrase string, data *VaultData) error {
	if passphrase == "" {
		return errors.New("passphrase cannot be empty")
	}
	if data == nil || !identity.ValidateMnemonic(data.Mnemonic) {
		return errors.New("vault data contains invalid mnemonic")
	}
	if data.Origins == nil {
		data.Origins = make(map[string]OriginState)
	}
	if data.Sessions == nil {
		data.Sessions = make(map[string]string)
	}

	plaintext, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal vault data: %w", err)
	}
	defer identity.ZeroBytes(plaintext)

	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}

	key := argon2.IDKey([]byte(passphrase), salt, defaultArgonTime, defaultArgonMemory, defaultArgonThreads, chacha20poly1305.KeySize)
	defer identity.ZeroBytes(key)

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return fmt.Errorf("init xchacha20-poly1305: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, []byte(vaultAAD))

	fileObj := encryptedVaultFile{
		Version:    vaultVersion,
		KDF:        "argon2id",
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Time:       defaultArgonTime,
		MemoryKB:   defaultArgonMemory,
		Threads:    defaultArgonThreads,
		Cipher:     "xchacha20-poly1305",
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}

	encoded, err := json.MarshalIndent(fileObj, "", "  ")
	if err != nil {
		return fmt.Errorf("encode vault file: %w", err)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create vault directory: %w", err)
	}

	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, encoded, 0o600); err != nil {
		return fmt.Errorf("write temp vault: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("finalize vault file: %w", err)
	}
	return nil
}

// OpenVault reads, authenticates, and decrypts an encrypted vault file using the passphrase.
func OpenVault(path, passphrase string) (*VaultData, error) {
	if passphrase == "" {
		return nil, errors.New("passphrase cannot be empty")
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read vault file: %w", err)
	}

	var fileObj encryptedVaultFile
	if err := json.Unmarshal(raw, &fileObj); err != nil {
		return nil, fmt.Errorf("parse vault file: %w", err)
	}
	if fileObj.Version != vaultVersion || fileObj.KDF != "argon2id" || fileObj.Cipher != "xchacha20-poly1305" {
		return nil, errors.New("unsupported vault format")
	}

	salt, err := base64.StdEncoding.DecodeString(fileObj.Salt)
	if err != nil {
		return nil, fmt.Errorf("decode salt: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(fileObj.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(fileObj.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}

	key := argon2.IDKey([]byte(passphrase), salt, fileObj.Time, fileObj.MemoryKB, fileObj.Threads, chacha20poly1305.KeySize)
	defer identity.ZeroBytes(key)

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("init xchacha20-poly1305: %w", err)
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, []byte(vaultAAD))
	if err != nil {
		return nil, errors.New("failed to decrypt vault (wrong passphrase or corrupted file)")
	}
	defer identity.ZeroBytes(plaintext)

	var data VaultData
	if err := json.Unmarshal(plaintext, &data); err != nil {
		return nil, fmt.Errorf("decode decrypted vault: %w", err)
	}
	if data.Origins == nil {
		data.Origins = make(map[string]OriginState)
	}
	if data.Sessions == nil {
		data.Sessions = make(map[string]string)
	}
	return &data, nil
}
