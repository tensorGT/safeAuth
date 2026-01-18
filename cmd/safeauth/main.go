package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/safeauth/safeauth/internal/identity"
	"github.com/safeauth/safeauth/internal/server"
	"github.com/safeauth/safeauth/internal/vault"
	"github.com/safeauth/safeauth/internal/zkring"
	"golang.org/x/term"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "init":
		err = cmdInit(args)
	case "restore":
		err = cmdRestore(args)
	case "derive":
		err = cmdDerive(args)
	case "register":
		err = cmdRegister(args)
	case "login":
		err = cmdLogin(args)
	case "rotate":
		err = cmdRotate(args)
	case "anon-login":
		err = cmdAnonLogin(args)
	case "session":
		err = cmdSession(args)
	case "agent":
		err = cmdAgent(args)
	case "-h", "--help", "help":
		printUsage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`safeauth - Zero-Password Local-First Authentication CLI

Usage:
  safeauth <command> [flags]

Commands:
  init        Generate a 128-bit BIP39 12-word seed phrase and create an encrypted vault
  restore     Restore an encrypted vault from an existing 12-word mnemonic (read via stdin/prompt)
  derive      Derive and display public identity info (account_id, public_key) for an origin
  register    Register your origin-scoped public key & recovery key with an auth server
  login       Authenticate via Ed25519 challenge-response and store the session token
  rotate      Promote a new epoch key using your root-derived recovery key
  anon-login  Prove allowlist membership anonymously via a 1-out-of-N Schnorr ring signature
  session     Verify the stored session token against the auth server
  agent       Run the localhost keyring bridge for the web UI`)
}

func resolveVaultPath(flagVal string) (string, error) {
	if flagVal != "" {
		return flagVal, nil
	}
	return vault.DefaultVaultPath()
}

func readSecret(prompt string) (string, error) {
	if env := os.Getenv("SAFEAUTH_PASSPHRASE"); env != "" {
		return env, nil
	}
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, prompt)
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	vaultFlag := fs.String("vault", "", "Path to encrypted vault file (default ~/.safeauth/vault.json)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	vPath, err := resolveVaultPath(*vaultFlag)
	if err != nil {
		return err
	}
	if _, err := os.Stat(vPath); err == nil {
		return fmt.Errorf("vault already exists at %s", vPath)
	}

	pass, err := readSecret("Enter vault passphrase: ")
	if err != nil {
		return err
	}
	if len(pass) < 8 {
		return errors.New("passphrase must be at least 8 characters")
	}

	mnemonic, err := identity.GenerateMnemonic128()
	if err != nil {
		return err
	}

	data := &vault.VaultData{
		Mnemonic: mnemonic,
		Origins:  make(map[string]vault.OriginState),
		Sessions: make(map[string]string),
	}
	if err := vault.SaveVault(vPath, pass, data); err != nil {
		return err
	}

	fmt.Printf("Encrypted vault created at: %s\n", vPath)
	fmt.Println("Write down your 12-word recovery seed phrase (never stored in plaintext):")
	fmt.Printf("\n  %s\n\n", mnemonic)
	return nil
}

func cmdRestore(args []string) error {
	fs := flag.NewFlagSet("restore", flag.ExitOnError)
	vaultFlag := fs.String("vault", "", "Path to encrypted vault file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	vPath, err := resolveVaultPath(*vaultFlag)
	if err != nil {
		return err
	}

	fmt.Fprint(os.Stderr, "Enter 12-word BIP39 mnemonic: ")
	reader := bufio.NewReader(os.Stdin)
	mnemonic, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	mnemonic = strings.Join(strings.Fields(strings.TrimSpace(mnemonic)), " ")
	if !identity.ValidateMnemonic(mnemonic) {
		return errors.New("invalid BIP39 mnemonic phrase")
	}

	pass, err := readSecret("Enter new vault passphrase: ")
	if err != nil {
		return err
	}
	if len(pass) < 8 {
		return errors.New("passphrase must be at least 8 characters")
	}

	data := &vault.VaultData{
		Mnemonic: mnemonic,
		Origins:  make(map[string]vault.OriginState),
		Sessions: make(map[string]string),
	}
	if err := vault.SaveVault(vPath, pass, data); err != nil {
		return err
	}
	fmt.Printf("Vault restored at: %s\n", vPath)
	return nil
}

func openUserVault(vaultFlag string) (string, string, *vault.VaultData, error) {
	vPath, err := resolveVaultPath(vaultFlag)
	if err != nil {
		return "", "", nil, err
	}
	pass, err := readSecret("Enter vault passphrase: ")
	if err != nil {
		return "", "", nil, err
	}
	data, err := vault.OpenVault(vPath, pass)
	if err != nil {
		return "", "", nil, err
	}
	return vPath, pass, data, nil
}

func cmdDerive(args []string) error {
	fs := flag.NewFlagSet("derive", flag.ExitOnError)
	vaultFlag := fs.String("vault", "", "Path to encrypted vault file")
	originFlag := fs.String("origin", "", "Service origin (e.g. auth.example.com)")
	indexFlag := fs.Uint("index", 0, "Account index")
	epochFlag := fs.Uint("epoch", 0, "Key rotation epoch")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *originFlag == "" {
		return errors.New("--origin is required")
	}

	_, _, data, err := openUserVault(*vaultFlag)
	if err != nil {
		return err
	}
	seed, err := identity.MasterSeedFromMnemonic(data.Mnemonic, "")
	if err != nil {
		return err
	}
	defer identity.ZeroBytes(seed)

	kp, err := identity.DeriveServiceKeys(seed, *originFlag, uint32(*indexFlag), uint32(*epochFlag))
	if err != nil {
		return err
	}
	defer kp.Wipe()

	fmt.Printf("Origin:              %s\n", kp.Origin)
	fmt.Printf("Account Index:       %d\n", kp.AccountIndex)
	fmt.Printf("Epoch:               %d\n", kp.Epoch)
	fmt.Printf("Account ID:          %s\n", kp.AccountID)
	fmt.Printf("Public Key:          %s\n", base64.StdEncoding.EncodeToString(kp.PublicKey))
	fmt.Printf("Recovery Public Key: %s\n", base64.StdEncoding.EncodeToString(kp.RecoveryPubKey))
	return nil
}

func performRegister(vPath, pass string, data *vault.VaultData, serverURL, rawOrigin string, index uint32) (*identity.ServiceKeypair, error) {
	seed, err := identity.MasterSeedFromMnemonic(data.Mnemonic, "")
	if err != nil {
		return nil, err
	}
	defer identity.ZeroBytes(seed)

	kp, err := identity.DeriveServiceKeys(seed, rawOrigin, index, 0)
	if err != nil {
		return nil, err
	}

	var out map[string]any
	status, err := postJSON(serverURL+"/register", map[string]string{
		"account_id":          kp.AccountID,
		"public_key":          base64.StdEncoding.EncodeToString(kp.PublicKey),
		"recovery_public_key": base64.StdEncoding.EncodeToString(kp.RecoveryPubKey),
	}, &out)
	if err != nil {
		kp.Wipe()
		return nil, err
	}
	if status != http.StatusCreated {
		kp.Wipe()
		return nil, fmt.Errorf("register failed (%d): %v", status, out["error"])
	}

	data.Origins[kp.Origin] = vault.OriginState{AccountIndex: kp.AccountIndex, Epoch: 0}
	if err := vault.SaveVault(vPath, pass, data); err != nil {
		kp.Wipe()
		return nil, err
	}
	return kp, nil
}

func performLogin(vPath, pass string, data *vault.VaultData, serverURL, rawOrigin string) (string, int64, *identity.ServiceKeypair, error) {
	origin, err := identity.CanonicalOrigin(rawOrigin)
	if err != nil {
		return "", 0, nil, err
	}
	state := data.Origins[origin]

	seed, err := identity.MasterSeedFromMnemonic(data.Mnemonic, "")
	if err != nil {
		return "", 0, nil, err
	}
	defer identity.ZeroBytes(seed)

	kp, err := identity.DeriveServiceKeys(seed, origin, state.AccountIndex, state.Epoch)
	if err != nil {
		return "", 0, nil, err
	}

	var ch struct {
		ChallengeID string `json:"challenge_id"`
		Nonce       string `json:"nonce"`
		Error       string `json:"error"`
	}
	status, err := postJSON(serverURL+"/challenge", map[string]string{
		"account_id": kp.AccountID,
		"purpose":    "login",
	}, &ch)
	if err != nil {
		kp.Wipe()
		return "", 0, nil, err
	}
	if status != http.StatusOK {
		kp.Wipe()
		return "", 0, nil, fmt.Errorf("challenge failed (%d): %s", status, ch.Error)
	}

	ts := time.Now().Unix()
	sig := identity.SignLoginChallenge(kp.PrivateKey, kp.Origin, kp.AccountID, ch.Nonce, ts)

	var verifyResp struct {
		SessionToken string `json:"session_token"`
		ExpiresAt    int64  `json:"expires_at"`
		Error        string `json:"error"`
	}
	status, err = postJSON(serverURL+"/verify", map[string]any{
		"challenge_id": ch.ChallengeID,
		"account_id":   kp.AccountID,
		"timestamp":    ts,
		"signature":    base64.StdEncoding.EncodeToString(sig),
	}, &verifyResp)
	if err != nil {
		kp.Wipe()
		return "", 0, nil, err
	}
	if status != http.StatusOK {
		kp.Wipe()
		return "", 0, nil, fmt.Errorf("login failed (%d): %s", status, verifyResp.Error)
	}

	data.Sessions[kp.Origin] = verifyResp.SessionToken
	if err := vault.SaveVault(vPath, pass, data); err != nil {
		kp.Wipe()
		return "", 0, nil, err
	}
	return verifyResp.SessionToken, verifyResp.ExpiresAt, kp, nil
}

func performRotate(vPath, pass string, data *vault.VaultData, serverURL, rawOrigin string) (*identity.ServiceKeypair, error) {
	origin, err := identity.CanonicalOrigin(rawOrigin)
	if err != nil {
		return nil, err
	}
	state := data.Origins[origin]
	nextEpoch := state.Epoch + 1

	seed, err := identity.MasterSeedFromMnemonic(data.Mnemonic, "")
	if err != nil {
		return nil, err
	}
	defer identity.ZeroBytes(seed)

	newKP, err := identity.DeriveServiceKeys(seed, origin, state.AccountIndex, nextEpoch)
	if err != nil {
		return nil, err
	}

	var ch struct {
		ChallengeID string `json:"challenge_id"`
		Nonce       string `json:"nonce"`
		Error       string `json:"error"`
	}
	status, err := postJSON(serverURL+"/challenge", map[string]string{
		"account_id": newKP.AccountID,
		"purpose":    "rotate",
	}, &ch)
	if err != nil {
		newKP.Wipe()
		return nil, err
	}
	if status != http.StatusOK {
		newKP.Wipe()
		return nil, fmt.Errorf("rotation challenge failed (%d): %s", status, ch.Error)
	}

	ts := time.Now().Unix()
	sig := identity.SignRotateChallenge(newKP.RecoveryPrivKey, newKP.Origin, newKP.AccountID, newKP.PublicKey, ch.Nonce, ts)

	var out map[string]any
	status, err = postJSON(serverURL+"/rotate", map[string]any{
		"challenge_id":   ch.ChallengeID,
		"account_id":     newKP.AccountID,
		"new_public_key": base64.StdEncoding.EncodeToString(newKP.PublicKey),
		"timestamp":      ts,
		"signature":      base64.StdEncoding.EncodeToString(sig),
	}, &out)
	if err != nil {
		newKP.Wipe()
		return nil, err
	}
	if status != http.StatusOK {
		newKP.Wipe()
		return nil, fmt.Errorf("rotate failed (%d): %v", status, out["error"])
	}

	state.Epoch = nextEpoch
	data.Origins[origin] = state
	if err := vault.SaveVault(vPath, pass, data); err != nil {
		newKP.Wipe()
		return nil, err
	}
	return newKP, nil
}

func performAnonLogin(vPath, pass string, data *vault.VaultData, serverURL, rawOrigin string) (string, int, error) {
	origin, err := identity.CanonicalOrigin(rawOrigin)
	if err != nil {
		return "", 0, err
	}
	state := data.Origins[origin]

	seed, err := identity.MasterSeedFromMnemonic(data.Mnemonic, "")
	if err != nil {
		return "", 0, err
	}
	defer identity.ZeroBytes(seed)

	kp, err := identity.DeriveServiceKeys(seed, origin, state.AccountIndex, state.Epoch)
	if err != nil {
		return "", 0, err
	}
	defer kp.Wipe()

	resp, err := http.Get(serverURL + "/allowlist")
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	var allowOut struct {
		PublicKeys []string `json:"public_keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&allowOut); err != nil {
		return "", 0, err
	}
	if len(allowOut.PublicKeys) == 0 {
		return "", 0, errors.New("server allowlist is empty")
	}

	ring := make([]ed25519.PublicKey, 0, len(allowOut.PublicKeys))
	for _, pkB64 := range allowOut.PublicKeys {
		b, err := base64.StdEncoding.DecodeString(pkB64)
		if err != nil || len(b) != ed25519.PublicKeySize {
			return "", 0, errors.New("invalid public key in allowlist")
		}
		ring = append(ring, ed25519.PublicKey(b))
	}

	var ch struct {
		ChallengeID string `json:"challenge_id"`
		Nonce       string `json:"nonce"`
		Error       string `json:"error"`
	}
	status, err := postJSON(serverURL+"/challenge", map[string]string{
		"purpose": "anon",
	}, &ch)
	if err != nil {
		return "", 0, err
	}
	if status != http.StatusOK {
		return "", 0, fmt.Errorf("anon challenge failed (%d): %s", status, ch.Error)
	}

	ts := time.Now().Unix()
	msg := server.AnonLoginPayload(kp.Origin, ch.Nonce, ts)
	ringSig, err := zkring.SignRing(msg, ring, kp.PrivateKey)
	if err != nil {
		return "", 0, err
	}

	var anonOut struct {
		SessionToken string `json:"session_token"`
		ExpiresAt    int64  `json:"expires_at"`
		Error        string `json:"error"`
	}
	status, err = postJSON(serverURL+"/anon-verify", map[string]any{
		"challenge_id":   ch.ChallengeID,
		"timestamp":      ts,
		"public_keys":    allowOut.PublicKeys,
		"ring_signature": ringSig,
	}, &anonOut)
	if err != nil {
		return "", 0, err
	}
	if status != http.StatusOK {
		return "", 0, fmt.Errorf("anonymous login failed (%d): %s", status, anonOut.Error)
	}

	data.Sessions[kp.Origin] = anonOut.SessionToken
	if err := vault.SaveVault(vPath, pass, data); err != nil {
		return "", 0, err
	}
	return anonOut.SessionToken, len(ring), nil
}

func cmdRegister(args []string) error {
	fs := flag.NewFlagSet("register", flag.ExitOnError)
	vaultFlag := fs.String("vault", "", "Path to encrypted vault file")
	serverFlag := fs.String("server", "http://localhost:8080", "Auth server base URL")
	originFlag := fs.String("origin", "localhost:8080", "Service origin")
	indexFlag := fs.Uint("index", 0, "Account index")
	if err := fs.Parse(args); err != nil {
		return err
	}

	vPath, pass, data, err := openUserVault(*vaultFlag)
	if err != nil {
		return err
	}
	kp, err := performRegister(vPath, pass, data, *serverFlag, *originFlag, uint32(*indexFlag))
	if err != nil {
		return err
	}
	defer kp.Wipe()

	fmt.Printf("Registered account %s on %s (epoch=0)\n", kp.AccountID, kp.Origin)
	return nil
}

func cmdLogin(args []string) error {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	vaultFlag := fs.String("vault", "", "Path to encrypted vault file")
	serverFlag := fs.String("server", "http://localhost:8080", "Auth server base URL")
	originFlag := fs.String("origin", "localhost:8080", "Service origin")
	if err := fs.Parse(args); err != nil {
		return err
	}

	vPath, pass, data, err := openUserVault(*vaultFlag)
	if err != nil {
		return err
	}
	token, exp, kp, err := performLogin(vPath, pass, data, *serverFlag, *originFlag)
	if err != nil {
		return err
	}
	defer kp.Wipe()

	fmt.Printf("Login successful for %s (epoch=%d)\n", kp.AccountID, kp.Epoch)
	fmt.Printf("Session Token: %s\n", token)
	fmt.Printf("Expires At:    %s\n", time.Unix(exp, 0).Format(time.RFC3339))
	return nil
}

func cmdRotate(args []string) error {
	fs := flag.NewFlagSet("rotate", flag.ExitOnError)
	vaultFlag := fs.String("vault", "", "Path to encrypted vault file")
	serverFlag := fs.String("server", "http://localhost:8080", "Auth server base URL")
	originFlag := fs.String("origin", "localhost:8080", "Service origin")
	if err := fs.Parse(args); err != nil {
		return err
	}

	vPath, pass, data, err := openUserVault(*vaultFlag)
	if err != nil {
		return err
	}
	newKP, err := performRotate(vPath, pass, data, *serverFlag, *originFlag)
	if err != nil {
		return err
	}
	defer newKP.Wipe()

	fmt.Printf("Rotated key for %s on %s -> epoch %d\n", newKP.AccountID, newKP.Origin, newKP.Epoch)
	fmt.Printf("New Public Key: %s\n", base64.StdEncoding.EncodeToString(newKP.PublicKey))
	return nil
}

func cmdAnonLogin(args []string) error {
	fs := flag.NewFlagSet("anon-login", flag.ExitOnError)
	vaultFlag := fs.String("vault", "", "Path to encrypted vault file")
	serverFlag := fs.String("server", "http://localhost:8080", "Auth server base URL")
	originFlag := fs.String("origin", "localhost:8080", "Service origin")
	if err := fs.Parse(args); err != nil {
		return err
	}

	vPath, pass, data, err := openUserVault(*vaultFlag)
	if err != nil {
		return err
	}
	token, ringSize, err := performAnonLogin(vPath, pass, data, *serverFlag, *originFlag)
	if err != nil {
		return err
	}

	fmt.Printf("Anonymous ring-proof login successful (ring size=%d)\n", ringSize)
	fmt.Printf("Session Token: %s\n", token)
	return nil
}

func cmdAgent(args []string) error {
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	vaultFlag := fs.String("vault", "", "Path to encrypted vault file")
	serverFlag := fs.String("server", "http://localhost:8080", "Auth server base URL")
	originFlag := fs.String("origin", "localhost:8080", "Service origin")
	addrFlag := fs.String("addr", "127.0.0.1:9090", "Local agent HTTP listen address")
	if err := fs.Parse(args); err != nil {
		return err
	}

	vPath, pass, data, err := openUserVault(*vaultFlag)
	if err != nil {
		return err
	}
	origin, err := identity.CanonicalOrigin(*originFlag)
	if err != nil {
		return err
	}

	var mu sync.Mutex
	writeAgentJSON := func(w http.ResponseWriter, status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		state := data.Origins[origin]
		seed, err := identity.MasterSeedFromMnemonic(data.Mnemonic, "")
		if err != nil {
			writeAgentJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		defer identity.ZeroBytes(seed)
		kp, err := identity.DeriveServiceKeys(seed, origin, state.AccountIndex, state.Epoch)
		if err != nil {
			writeAgentJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		defer kp.Wipe()
		writeAgentJSON(w, http.StatusOK, map[string]any{
			"unlocked":    true,
			"origin":      kp.Origin,
			"account_id":  kp.AccountID,
			"epoch":       kp.Epoch,
			"public_key":  base64.StdEncoding.EncodeToString(kp.PublicKey),
			"has_session": data.Sessions[origin] != "",
		})
	})

	mux.HandleFunc("POST /action/register", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		kp, err := performRegister(vPath, pass, data, *serverFlag, origin, 0)
		if err != nil {
			writeAgentJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		defer kp.Wipe()
		writeAgentJSON(w, http.StatusCreated, map[string]any{
			"account_id": kp.AccountID,
			"origin":     kp.Origin,
			"epoch":      kp.Epoch,
		})
	})

	mux.HandleFunc("POST /action/login", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		token, exp, kp, err := performLogin(vPath, pass, data, *serverFlag, origin)
		if err != nil {
			writeAgentJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
			return
		}
		defer kp.Wipe()
		writeAgentJSON(w, http.StatusOK, map[string]any{
			"session_token": token,
			"expires_at":    exp,
			"account_id":    kp.AccountID,
			"epoch":         kp.Epoch,
		})
	})

	mux.HandleFunc("POST /action/rotate", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		newKP, err := performRotate(vPath, pass, data, *serverFlag, origin)
		if err != nil {
			writeAgentJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		defer newKP.Wipe()
		writeAgentJSON(w, http.StatusOK, map[string]any{
			"account_id": newKP.AccountID,
			"epoch":      newKP.Epoch,
			"public_key": base64.StdEncoding.EncodeToString(newKP.PublicKey),
		})
	})

	mux.HandleFunc("POST /action/anon-login", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		token, ringSize, err := performAnonLogin(vPath, pass, data, *serverFlag, origin)
		if err != nil {
			writeAgentJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
			return
		}
		writeAgentJSON(w, http.StatusOK, map[string]any{
			"session_token": token,
			"anonymous":     true,
			"ring_size":     ringSize,
		})
	})

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", *serverFlag)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		mux.ServeHTTP(w, r)
	})

	fmt.Printf("safeauth local agent listening on http://%s (bridging %s, origin=%s)\n", *addrFlag, *serverFlag, origin)
	return http.ListenAndServe(*addrFlag, handler)
}

func cmdSession(args []string) error {
	fs := flag.NewFlagSet("session", flag.ExitOnError)
	vaultFlag := fs.String("vault", "", "Path to encrypted vault file")
	serverFlag := fs.String("server", "http://localhost:8080", "Auth server base URL")
	originFlag := fs.String("origin", "localhost:8080", "Service origin")
	if err := fs.Parse(args); err != nil {
		return err
	}

	_, _, data, err := openUserVault(*vaultFlag)
	if err != nil {
		return err
	}
	origin, err := identity.CanonicalOrigin(*originFlag)
	if err != nil {
		return err
	}
	token := data.Sessions[origin]
	if token == "" {
		return fmt.Errorf("no stored session token for %s", origin)
	}

	req, err := http.NewRequest(http.MethodGet, *serverFlag+"/session", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("session check failed (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	fmt.Println(string(body))
	return nil
}

func postJSON(url string, payload any, out any) (int, error) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(payload); err != nil {
		return 0, err
	}
	resp, err := http.Post(url, "application/json", &buf)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if out != nil {
		_ = json.NewDecoder(resp.Body).Decode(out)
	}
	return resp.StatusCode, nil
}
