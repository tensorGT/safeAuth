package zkring

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestRingSignatureSignAndVerify(t *testing.T) {
	ring := make([]ed25519.PublicKey, 5)
	privs := make([]ed25519.PrivateKey, 5)
	for i := 0; i < 5; i++ {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		ring[i] = pub
		privs[i] = priv
	}

	msg := []byte("safeauth-anon-v1\nauth.example.com\nnonce-123\n1700000000")

	// Sign as member index 2 (middle of ring).
	sig, err := SignRing(msg, ring, privs[2])
	if err != nil {
		t.Fatalf("SignRing: %v", err)
	}
	if !VerifyRing(msg, ring, sig) {
		t.Fatalf("valid ring signature failed verification")
	}

	// Wrong message must fail.
	if VerifyRing([]byte("tampered-message"), ring, sig) {
		t.Fatalf("ring signature verified on wrong message")
	}

	// Altered ring must fail.
	otherPub, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	badRing := append([]ed25519.PublicKey(nil), ring...)
	badRing[0] = otherPub
	if VerifyRing(msg, badRing, sig) {
		t.Fatalf("ring signature verified on altered ring")
	}

	// Non-member cannot sign for the ring.
	if _, err := SignRing(msg, ring, otherPriv); err == nil {
		t.Fatalf("expected non-member SignRing to fail")
	}
}
