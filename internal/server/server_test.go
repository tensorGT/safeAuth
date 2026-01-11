package server

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/safeauth/safeauth/internal/identity"
	"github.com/safeauth/safeauth/internal/zkring"
)

func doJSON(t *testing.T, client *http.Client, method, url string, body any) *http.Response {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode request: %v", err)
		}
	}
	req, err := http.NewRequest(method, url, &buf)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("http %s %s: %v", method, url, err)
	}
	return resp
}

func TestFullLoginRotationReplayAndAnonFlow(t *testing.T) {
	now := time.Unix(1700000000, 0)
	srv, err := New(Config{
		Origin:         "auth.example.com",
		RateLimitPerIP: 0,
		Now:            func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	client := ts.Client()

	mnemonic, _ := identity.GenerateMnemonic128()
	seed, _ := identity.MasterSeedFromMnemonic(mnemonic, "")
	k0, _ := identity.DeriveServiceKeys(seed, "auth.example.com", 0, 0)

	// 1. Register account (only public keys, no password/PII).
	resp := doJSON(t, client, http.MethodPost, ts.URL+"/register", map[string]string{
		"account_id":          k0.AccountID,
		"public_key":          base64.StdEncoding.EncodeToString(k0.PublicKey),
		"recovery_public_key": base64.StdEncoding.EncodeToString(k0.RecoveryPubKey),
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register expected 201, got %d", resp.StatusCode)
	}

	// 2. Unknown account challenge must still return 200 with indistinguishable shape.
	resp = doJSON(t, client, http.MethodPost, ts.URL+"/challenge", map[string]string{
		"account_id": "nonexistent-account-id",
	})
	var unknownCh challengeResponse
	_ = json.NewDecoder(resp.Body).Decode(&unknownCh)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || unknownCh.Nonce == "" || unknownCh.ChallengeID == "" {
		t.Fatalf("unknown account challenge leaked existence: status=%d", resp.StatusCode)
	}

	// 3. Valid challenge-response login.
	resp = doJSON(t, client, http.MethodPost, ts.URL+"/challenge", map[string]string{
		"account_id": k0.AccountID,
	})
	var ch challengeResponse
	_ = json.NewDecoder(resp.Body).Decode(&ch)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("challenge expected 200, got %d", resp.StatusCode)
	}

	sig := identity.SignLoginChallenge(k0.PrivateKey, k0.Origin, k0.AccountID, ch.Nonce, now.Unix())
	resp = doJSON(t, client, http.MethodPost, ts.URL+"/verify", map[string]any{
		"challenge_id": ch.ChallengeID,
		"account_id":   k0.AccountID,
		"timestamp":    now.Unix(),
		"signature":    base64.StdEncoding.EncodeToString(sig),
	})
	var verifyOut map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&verifyOut)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || verifyOut["session_token"] == "" {
		t.Fatalf("verify failed: status=%d", resp.StatusCode)
	}
	token := verifyOut["session_token"].(string)

	// 4. Replay of the exact same challenge must fail with 401.
	resp = doJSON(t, client, http.MethodPost, ts.URL+"/verify", map[string]any{
		"challenge_id": ch.ChallengeID,
		"account_id":   k0.AccountID,
		"timestamp":    now.Unix(),
		"signature":    base64.StdEncoding.EncodeToString(sig),
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replayed challenge should return 401, got %d", resp.StatusCode)
	}

	// 5. Validate minted session token via /session.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/session", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("GET /session: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /session expected 200, got %d", resp.StatusCode)
	}

	// 6. Expired challenge must fail.
	resp = doJSON(t, client, http.MethodPost, ts.URL+"/challenge", map[string]string{
		"account_id": k0.AccountID,
	})
	var chExp challengeResponse
	_ = json.NewDecoder(resp.Body).Decode(&chExp)
	resp.Body.Close()
	now = now.Add(ChallengeTTL + 5*time.Second)
	sigExp := identity.SignLoginChallenge(k0.PrivateKey, k0.Origin, k0.AccountID, chExp.Nonce, now.Unix())
	resp = doJSON(t, client, http.MethodPost, ts.URL+"/verify", map[string]any{
		"challenge_id": chExp.ChallengeID,
		"account_id":   k0.AccountID,
		"timestamp":    now.Unix(),
		"signature":    base64.StdEncoding.EncodeToString(sigExp),
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expired challenge should return 401, got %d", resp.StatusCode)
	}

	// 7. Key Rotation via root-derived recovery key (promoting epoch 1).
	k1, _ := identity.DeriveServiceKeys(seed, "auth.example.com", 0, 1)
	resp = doJSON(t, client, http.MethodPost, ts.URL+"/challenge", map[string]string{
		"account_id": k0.AccountID,
		"purpose":    "rotate",
	})
	var chRot challengeResponse
	_ = json.NewDecoder(resp.Body).Decode(&chRot)
	resp.Body.Close()

	rotSig := identity.SignRotateChallenge(k0.RecoveryPrivKey, k0.Origin, k0.AccountID, k1.PublicKey, chRot.Nonce, now.Unix())
	resp = doJSON(t, client, http.MethodPost, ts.URL+"/rotate", map[string]any{
		"challenge_id":   chRot.ChallengeID,
		"account_id":     k0.AccountID,
		"new_public_key": base64.StdEncoding.EncodeToString(k1.PublicKey),
		"timestamp":      now.Unix(),
		"signature":      base64.StdEncoding.EncodeToString(rotSig),
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rotate expected 200, got %d", resp.StatusCode)
	}

	// Old key k0 must now be rejected, and new key k1 must succeed.
	resp = doJSON(t, client, http.MethodPost, ts.URL+"/challenge", map[string]string{"account_id": k0.AccountID})
	var chAfterRot challengeResponse
	_ = json.NewDecoder(resp.Body).Decode(&chAfterRot)
	resp.Body.Close()
	oldSig := identity.SignLoginChallenge(k0.PrivateKey, k0.Origin, k0.AccountID, chAfterRot.Nonce, now.Unix())
	resp = doJSON(t, client, http.MethodPost, ts.URL+"/verify", map[string]any{
		"challenge_id": chAfterRot.ChallengeID,
		"account_id":   k0.AccountID,
		"timestamp":    now.Unix(),
		"signature":    base64.StdEncoding.EncodeToString(oldSig),
	})
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("compromised old key should fail after rotation, got %d", resp.StatusCode)
	}

	// 8. Anonymous allowlist ring signature proof (/anon-verify).
	// Register a second member so the ring has >= 2 members.
	m2, _ := identity.GenerateMnemonic128()
	s2, _ := identity.MasterSeedFromMnemonic(m2, "")
	other, _ := identity.DeriveServiceKeys(s2, "auth.example.com", 0, 0)
	resp = doJSON(t, client, http.MethodPost, ts.URL+"/register", map[string]string{
		"account_id":          other.AccountID,
		"public_key":          base64.StdEncoding.EncodeToString(other.PublicKey),
		"recovery_public_key": base64.StdEncoding.EncodeToString(other.RecoveryPubKey),
	})
	resp.Body.Close()

	resp = doJSON(t, client, http.MethodPost, ts.URL+"/challenge", map[string]string{"purpose": "anon"})
	var chAnon challengeResponse
	_ = json.NewDecoder(resp.Body).Decode(&chAnon)
	resp.Body.Close()

	ring := []ed25519.PublicKey{k1.PublicKey, other.PublicKey}
	ringB64 := []string{
		base64.StdEncoding.EncodeToString(k1.PublicKey),
		base64.StdEncoding.EncodeToString(other.PublicKey),
	}
	anonMsg := AnonLoginPayload(k1.Origin, chAnon.Nonce, now.Unix())
	ringSig, err := zkring.SignRing(anonMsg, ring, k1.PrivateKey)
	if err != nil {
		t.Fatalf("SignRing: %v", err)
	}

	resp = doJSON(t, client, http.MethodPost, ts.URL+"/anon-verify", map[string]any{
		"challenge_id":   chAnon.ChallengeID,
		"timestamp":      now.Unix(),
		"public_keys":    ringB64,
		"ring_signature": ringSig,
	})
	var anonOut map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&anonOut)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || anonOut["anonymous"] != true {
		t.Fatalf("anon-verify failed: status=%d", resp.StatusCode)
	}
}

func TestRateLimiting(t *testing.T) {
	srv, err := New(Config{
		Origin:         "auth.example.com",
		RateLimitPerIP: 1,
		RateBurst:      2,
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	for i := 0; i < 2; i++ {
		resp, _ := ts.Client().Get(ts.URL + "/health")
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d expected 200, got %d", i, resp.StatusCode)
		}
	}
	resp, _ := ts.Client().Get(ts.URL + "/health")
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after burst exhausted, got %d", resp.StatusCode)
	}
}
