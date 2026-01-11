package server

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/safeauth/safeauth/internal/identity"
	"github.com/safeauth/safeauth/internal/zkring"
)

//go:embed ui/*
var uiFS embed.FS

const (
	ChallengeTTL       = 60 * time.Second
	AllowedClockSkew   = 30 * time.Second
	SessionTokenTTL    = 15 * time.Minute
	NonceSize          = 32
	MaxRequestBodySize = 64 * 1024 // 64 KiB
)

// Config configures the AuthServer.
type Config struct {
	Origin         string
	TokenSecret    []byte
	RateLimitPerIP float64 // tokens per second; <= 0 disables rate limiting
	RateBurst      int
	Now            func() time.Time
}

type accountRecord struct {
	AccountID      string
	ActivePubKey   ed25519.PublicKey
	RecoveryPubKey ed25519.PublicKey
	Epoch          uint32
	CreatedAt      time.Time
}

type challengeRecord struct {
	ID            string
	AccountID     string
	Purpose       string // "login", "rotate", "anon"
	NonceB64      string
	ExpiresAt     time.Time
	AccountExists bool
}

// SessionClaims represents the verified payload of a minted session token.
type SessionClaims struct {
	Sub       string `json:"sub"`
	Origin    string `json:"origin"`
	Anonymous bool   `json:"anonymous"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	JTI       string `json:"jti"`
}

type tokenBucket struct {
	tokens   float64
	lastSeen time.Time
}

// AuthServer implements the zero-password Ed25519 challenge-response auth server.
type AuthServer struct {
	origin      string
	tokenSecret []byte
	now         func() time.Time

	mu         sync.Mutex
	accounts   map[string]*accountRecord
	challenges map[string]*challengeRecord

	rlMu       sync.Mutex
	ratePerSec float64
	rateBurst  float64
	buckets    map[string]*tokenBucket
}

// New creates a new AuthServer for the given origin.
func New(cfg Config) (*AuthServer, error) {
	origin, err := identity.CanonicalOrigin(cfg.Origin)
	if err != nil {
		return nil, fmt.Errorf("invalid server origin: %w", err)
	}

	secret := cfg.TokenSecret
	if len(secret) == 0 {
		secret = make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, secret); err != nil {
			return nil, fmt.Errorf("generate token secret: %w", err)
		}
	}

	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
	}

	burst := cfg.RateBurst
	if cfg.RateLimitPerIP > 0 && burst <= 0 {
		burst = 10
	}

	return &AuthServer{
		origin:      origin,
		tokenSecret: secret,
		now:         nowFn,
		accounts:    make(map[string]*accountRecord),
		challenges:  make(map[string]*challengeRecord),
		ratePerSec:  cfg.RateLimitPerIP,
		rateBurst:   float64(burst),
		buckets:     make(map[string]*tokenBucket),
	}, nil
}

// Handler returns the HTTP handler with all auth routes and rate-limiting middleware.
func (s *AuthServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /register", s.handleRegister)
	mux.HandleFunc("POST /challenge", s.handleChallenge)
	mux.HandleFunc("POST /verify", s.handleVerify)
	mux.HandleFunc("POST /rotate", s.handleRotate)
	mux.HandleFunc("GET /session", s.handleSession)
	mux.HandleFunc("GET /allowlist", s.handleAllowlist)
	mux.HandleFunc("GET /accounts", s.handleAccounts)
	mux.HandleFunc("POST /anon-verify", s.handleAnonVerify)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "origin": s.origin})
	})

	subUI, err := fs.Sub(uiFS, "ui")
	if err == nil {
		mux.Handle("GET /", http.FileServer(http.FS(subUI)))
	}

	return s.rateLimitMiddleware(mux)
}

func (s *AuthServer) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.ratePerSec > 0 {
			ip := clientIP(r)
			if !s.allowIP(ip) {
				writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limit exceeded"})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *AuthServer) allowIP(ip string) bool {
	s.rlMu.Lock()
	defer s.rlMu.Unlock()

	now := s.now()
	b, ok := s.buckets[ip]
	if !ok {
		s.buckets[ip] = &tokenBucket{tokens: s.rateBurst - 1, lastSeen: now}
		return true
	}

	elapsed := now.Sub(b.lastSeen).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * s.ratePerSec
		if b.tokens > s.rateBurst {
			b.tokens = s.rateBurst
		}
	}
	b.lastSeen = now
	if b.tokens < 1.0 {
		return false
	}
	b.tokens -= 1.0
	return true
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

type registerRequest struct {
	AccountID      string `json:"account_id"`
	PublicKey      string `json:"public_key"`
	RecoveryPubKey string `json:"recovery_public_key"`
}

func (s *AuthServer) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if req.AccountID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "account_id is required"})
		return
	}
	pub, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid public_key"})
		return
	}
	recPub, err := base64.StdEncoding.DecodeString(req.RecoveryPubKey)
	if err != nil || len(recPub) != ed25519.PublicKeySize {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid recovery_public_key"})
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.accounts[req.AccountID]; exists {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "account already registered"})
		return
	}

	s.accounts[req.AccountID] = &accountRecord{
		AccountID:      req.AccountID,
		ActivePubKey:   ed25519.PublicKey(pub),
		RecoveryPubKey: ed25519.PublicKey(recPub),
		Epoch:          0,
		CreatedAt:      s.now(),
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"account_id": req.AccountID,
		"origin":     s.origin,
		"epoch":      0,
	})
}

type challengeRequest struct {
	AccountID string `json:"account_id"`
	Purpose   string `json:"purpose,omitempty"` // "login" (default), "rotate", "anon"
}

type challengeResponse struct {
	ChallengeID string `json:"challenge_id"`
	Origin      string `json:"origin"`
	Nonce       string `json:"nonce"`
	ExpiresAt   int64  `json:"expires_at"`
}

func (s *AuthServer) handleChallenge(w http.ResponseWriter, r *http.Request) {
	var req challengeRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	purpose := req.Purpose
	if purpose == "" {
		purpose = "login"
	}
	if purpose != "login" && purpose != "rotate" && purpose != "anon" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid challenge purpose"})
		return
	}
	if purpose != "anon" && req.AccountID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "account_id is required"})
		return
	}

	nonceBytes := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonceBytes); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}
	idBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, idBytes); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	now := s.now()
	expiresAt := now.Add(ChallengeTTL)
	challengeID := base64.RawURLEncoding.EncodeToString(idBytes)
	nonceB64 := base64.StdEncoding.EncodeToString(nonceBytes)

	s.mu.Lock()
	s.pruneExpiredChallengesLocked(now)
	_, exists := s.accounts[req.AccountID]
	// Store the challenge even if the account does not exist so response timing and format
	// do not leak whether account_id is registered.
	s.challenges[challengeID] = &challengeRecord{
		ID:            challengeID,
		AccountID:     req.AccountID,
		Purpose:       purpose,
		NonceB64:      nonceB64,
		ExpiresAt:     expiresAt,
		AccountExists: exists,
	}
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, challengeResponse{
		ChallengeID: challengeID,
		Origin:      s.origin,
		Nonce:       nonceB64,
		ExpiresAt:   expiresAt.Unix(),
	})
}

type verifyRequest struct {
	ChallengeID string `json:"challenge_id"`
	AccountID   string `json:"account_id"`
	Timestamp   int64  `json:"timestamp"`
	Signature   string `json:"signature"`
}

func (s *AuthServer) handleVerify(w http.ResponseWriter, r *http.Request) {
	var req verifyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	sig, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication failed"})
		return
	}

	now := s.now()
	ch, acct := s.consumeChallengeAndLookupAccount(req.ChallengeID, req.AccountID, "login", now)
	if ch == nil || acct == nil || !withinSkew(now, req.Timestamp) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication failed"})
		return
	}

	if !identity.VerifyLoginChallenge(acct.ActivePubKey, s.origin, acct.AccountID, ch.NonceB64, req.Timestamp, sig) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication failed"})
		return
	}

	token, exp, err := s.mintSessionToken(acct.AccountID, false)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"session_token": token,
		"expires_at":    exp.Unix(),
		"account_id":    acct.AccountID,
		"origin":        s.origin,
	})
}

type rotateRequest struct {
	ChallengeID  string `json:"challenge_id"`
	AccountID    string `json:"account_id"`
	NewPublicKey string `json:"new_public_key"`
	Timestamp    int64  `json:"timestamp"`
	Signature    string `json:"signature"`
}

func (s *AuthServer) handleRotate(w http.ResponseWriter, r *http.Request) {
	var req rotateRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	newPub, err := base64.StdEncoding.DecodeString(req.NewPublicKey)
	if err != nil || len(newPub) != ed25519.PublicKeySize {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid new_public_key"})
		return
	}
	sig, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication failed"})
		return
	}

	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()

	ch, ok := s.challenges[req.ChallengeID]
	if ok {
		delete(s.challenges, req.ChallengeID) // atomic single-use consumption
	}
	if !ok || ch.Purpose != "rotate" || ch.AccountID != req.AccountID || now.After(ch.ExpiresAt) || !withinSkew(now, req.Timestamp) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication failed"})
		return
	}

	acct, exists := s.accounts[req.AccountID]
	if !exists {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication failed"})
		return
	}

	if !identity.VerifyRotateChallenge(acct.RecoveryPubKey, s.origin, acct.AccountID, ed25519.PublicKey(newPub), ch.NonceB64, req.Timestamp, sig) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication failed"})
		return
	}

	acct.ActivePubKey = ed25519.PublicKey(newPub)
	acct.Epoch++

	writeJSON(w, http.StatusOK, map[string]any{
		"account_id": acct.AccountID,
		"origin":     s.origin,
		"epoch":      acct.Epoch,
	})
}

func (s *AuthServer) handleAllowlist(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	pubs := make([]string, 0, len(s.accounts))
	for _, acct := range s.accounts {
		pubs = append(pubs, base64.StdEncoding.EncodeToString(acct.ActivePubKey))
	}
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"origin":      s.origin,
		"public_keys": pubs,
	})
}

func (s *AuthServer) handleAccounts(w http.ResponseWriter, r *http.Request) {
	type publicAccountView struct {
		AccountID      string `json:"account_id"`
		PublicKey      string `json:"public_key"`
		RecoveryPubKey string `json:"recovery_public_key"`
		Epoch          uint32 `json:"epoch"`
		CreatedAt      string `json:"created_at"`
	}

	s.mu.Lock()
	list := make([]publicAccountView, 0, len(s.accounts))
	for _, acct := range s.accounts {
		list = append(list, publicAccountView{
			AccountID:      acct.AccountID,
			PublicKey:      base64.StdEncoding.EncodeToString(acct.ActivePubKey),
			RecoveryPubKey: base64.StdEncoding.EncodeToString(acct.RecoveryPubKey),
			Epoch:          acct.Epoch,
			CreatedAt:      acct.CreatedAt.UTC().Format(time.RFC3339),
		})
	}
	s.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"origin":   s.origin,
		"accounts": list,
	})
}

type anonVerifyRequest struct {
	ChallengeID   string                `json:"challenge_id"`
	Timestamp     int64                 `json:"timestamp"`
	PublicKeys    []string              `json:"public_keys"`
	RingSignature *zkring.RingSignature `json:"ring_signature"`
}

// AnonLoginPayload builds the canonical message signed by the 1-out-of-N ring signature.
func AnonLoginPayload(origin, nonceB64 string, timestamp int64) []byte {
	return []byte(fmt.Sprintf("safeauth-anon-v1\n%s\n%s\n%d", origin, nonceB64, timestamp))
}

func (s *AuthServer) handleAnonVerify(w http.ResponseWriter, r *http.Request) {
	var req anonVerifyRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	now := s.now()
	s.mu.Lock()
	ch, ok := s.challenges[req.ChallengeID]
	if ok {
		delete(s.challenges, req.ChallengeID)
	}
	// Snapshot registered keys to verify every key in the ring is genuinely allowlisted.
	allowedSet := make(map[string]struct{}, len(s.accounts))
	for _, acct := range s.accounts {
		allowedSet[base64.StdEncoding.EncodeToString(acct.ActivePubKey)] = struct{}{}
	}
	s.mu.Unlock()

	if !ok || ch.Purpose != "anon" || now.After(ch.ExpiresAt) || !withinSkew(now, req.Timestamp) || len(req.PublicKeys) == 0 {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication failed"})
		return
	}

	ring := make([]ed25519.PublicKey, 0, len(req.PublicKeys))
	for _, pkB64 := range req.PublicKeys {
		if _, isAllowed := allowedSet[pkB64]; !isAllowed {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication failed"})
			return
		}
		pkBytes, err := base64.StdEncoding.DecodeString(pkB64)
		if err != nil || len(pkBytes) != ed25519.PublicKeySize {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication failed"})
			return
		}
		ring = append(ring, ed25519.PublicKey(pkBytes))
	}

	msg := AnonLoginPayload(s.origin, ch.NonceB64, req.Timestamp)
	if !zkring.VerifyRing(msg, ring, req.RingSignature) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication failed"})
		return
	}

	token, exp, err := s.mintSessionToken("anonymous", true)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"session_token": token,
		"expires_at":    exp.Unix(),
		"anonymous":     true,
		"origin":        s.origin,
	})
}

func (s *AuthServer) handleSession(w http.ResponseWriter, r *http.Request) {
	authz := r.Header.Get("Authorization")
	if !strings.HasPrefix(authz, "Bearer ") {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing bearer token"})
		return
	}
	token := strings.TrimPrefix(authz, "Bearer ")
	claims, err := s.VerifySessionToken(token)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid or expired session"})
		return
	}
	writeJSON(w, http.StatusOK, claims)
}

func (s *AuthServer) consumeChallengeAndLookupAccount(challengeID, accountID, purpose string, now time.Time) (*challengeRecord, *accountRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ch, ok := s.challenges[challengeID]
	if ok {
		delete(s.challenges, challengeID) // single-use atomic consumption
	}
	if !ok || ch.Purpose != purpose || ch.AccountID != accountID || now.After(ch.ExpiresAt) {
		return nil, nil
	}
	acct := s.accounts[accountID]
	return ch, acct
}

func (s *AuthServer) pruneExpiredChallengesLocked(now time.Time) {
	for id, ch := range s.challenges {
		if now.After(ch.ExpiresAt) {
			delete(s.challenges, id)
		}
	}
}

func withinSkew(now time.Time, ts int64) bool {
	diff := now.Sub(time.Unix(ts, 0))
	if diff < 0 {
		diff = -diff
	}
	return diff <= AllowedClockSkew
}

func (s *AuthServer) mintSessionToken(sub string, anonymous bool) (string, time.Time, error) {
	now := s.now()
	exp := now.Add(SessionTokenTTL)
	jtiBytes := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, jtiBytes); err != nil {
		return "", time.Time{}, err
	}
	claims := SessionClaims{
		Sub:       sub,
		Origin:    s.origin,
		Anonymous: anonymous,
		IssuedAt:  now.Unix(),
		ExpiresAt: exp.Unix(),
		JTI:       base64.RawURLEncoding.EncodeToString(jtiBytes),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", time.Time{}, err
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)

	mac := hmac.New(sha256.New, s.tokenSecret)
	mac.Write([]byte(payloadB64))
	sigB64 := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return payloadB64 + "." + sigB64, exp, nil
}

// VerifySessionToken verifies an HMAC-SHA256 signed session token and checks expiration and origin.
func (s *AuthServer) VerifySessionToken(token string) (*SessionClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return nil, errors.New("malformed token")
	}
	payloadB64, sigB64 := parts[0], parts[1]

	mac := hmac.New(sha256.New, s.tokenSecret)
	mac.Write([]byte(payloadB64))
	expectedSig := mac.Sum(nil)

	gotSig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil || !hmac.Equal(expectedSig, gotSig) {
		return nil, errors.New("invalid token signature")
	}

	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, errors.New("invalid token encoding")
	}
	var claims SessionClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, errors.New("invalid token claims")
	}
	if claims.Origin != s.origin {
		return nil, errors.New("origin mismatch")
	}
	if s.now().Unix() > claims.ExpiresAt {
		return nil, errors.New("token expired")
	}
	return &claims, nil
}

func decodeJSON(r *http.Request, dst any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, MaxRequestBodySize))
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
