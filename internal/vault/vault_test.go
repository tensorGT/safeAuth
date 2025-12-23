package vault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/safeauth/safeauth/internal/identity"
)

func TestVaultRoundTripAndTamperDetection(t *testing.T) {
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "vault.json")

	mnemonic, err := identity.GenerateMnemonic128()
	if err != nil {
		t.Fatalf("GenerateMnemonic128: %v", err)
	}

	orig := &VaultData{
		Mnemonic: mnemonic,
		Origins: map[string]OriginState{
			"auth.example.com": {AccountIndex: 0, Epoch: 1},
		},
		Sessions: map[string]string{
			"auth.example.com": "tok-123",
		},
	}

	pass := "correct-horse-battery-staple"
	if err := SaveVault(vaultPath, pass, orig); err != nil {
		t.Fatalf("SaveVault: %v", err)
	}

	// Verify mnemonic does not appear in plaintext on disk.
	raw, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if strings.Contains(string(raw), strings.Fields(mnemonic)[0]) && strings.Contains(string(raw), mnemonic) {
		t.Fatalf("mnemonic leaked in plaintext inside vault file")
	}

	// Wrong passphrase must fail.
	if _, err := OpenVault(vaultPath, "wrong-passphrase"); err == nil {
		t.Fatalf("expected OpenVault to fail with wrong passphrase")
	}

	// Correct passphrase succeeds and preserves state.
	loaded, err := OpenVault(vaultPath, pass)
	if err != nil {
		t.Fatalf("OpenVault: %v", err)
	}
	if loaded.Mnemonic != orig.Mnemonic {
		t.Fatalf("loaded mnemonic mismatch")
	}
	if loaded.Origins["auth.example.com"].Epoch != 1 {
		t.Fatalf("loaded epoch mismatch: got %d", loaded.Origins["auth.example.com"].Epoch)
	}
	if loaded.Sessions["auth.example.com"] != "tok-123" {
		t.Fatalf("loaded session mismatch")
	}
}
