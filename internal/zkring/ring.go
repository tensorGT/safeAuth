package zkring

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"filippo.io/edwards25519"
)

const ringDomainTag = "safeauth-zkring-v1"

// RingSignature is a 1-out-of-N non-linkable Schnorr ring signature over Ed25519 public keys.
// It proves the signer possesses the private key for at least one public key in the ring
// without revealing which member signed.
type RingSignature struct {
	C0 string   `json:"c0"`
	R  []string `json:"r"`
}

func randomScalar() (*edwards25519.Scalar, error) {
	var buf [64]byte
	if _, err := io.ReadFull(rand.Reader, buf[:]); err != nil {
		return nil, err
	}
	return new(edwards25519.Scalar).SetUniformBytes(buf[:])
}

func ed25519PrivToScalar(priv ed25519.PrivateKey) (*edwards25519.Scalar, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid ed25519 private key length")
	}
	h := sha512.Sum512(priv.Seed())
	return new(edwards25519.Scalar).SetBytesWithClamping(h[:32])
}

func hashChallenge(msg []byte, ringBytes []byte, L *edwards25519.Point) (*edwards25519.Scalar, error) {
	h := sha512.New()
	h.Write([]byte(ringDomainTag))
	h.Write([]byte{0})
	h.Write(msg)
	h.Write([]byte{0})
	h.Write(ringBytes)
	h.Write([]byte{0})
	h.Write(L.Bytes())
	digest := h.Sum(nil)
	return new(edwards25519.Scalar).SetUniformBytes(digest)
}

func encodeRingPoints(ring []ed25519.PublicKey) ([]*edwards25519.Point, []byte, error) {
	if len(ring) == 0 {
		return nil, nil, errors.New("ring cannot be empty")
	}
	pts := make([]*edwards25519.Point, len(ring))
	buf := make([]byte, 0, len(ring)*ed25519.PublicKeySize)
	for i, pk := range ring {
		if len(pk) != ed25519.PublicKeySize {
			return nil, nil, fmt.Errorf("invalid public key size at index %d", i)
		}
		p, err := new(edwards25519.Point).SetBytes(pk)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid edwards25519 point at index %d: %w", i, err)
		}
		pts[i] = p
		buf = append(buf, pk...)
	}
	return pts, buf, nil
}

// SignRing creates a 1-out-of-N Schnorr ring signature for msg using signerPriv,
// where signerPriv.Public() must match one of the public keys in ring.
func SignRing(msg []byte, ring []ed25519.PublicKey, signerPriv ed25519.PrivateKey) (*RingSignature, error) {
	pts, ringBytes, err := encodeRingPoints(ring)
	if err != nil {
		return nil, err
	}
	signerPub := signerPriv.Public().(ed25519.PublicKey)
	signerIdx := -1
	for i, pk := range ring {
		if bytes.Equal(pk, signerPub) {
			signerIdx = i
			break
		}
	}
	if signerIdx < 0 {
		return nil, errors.New("signer public key is not a member of the ring")
	}

	x, err := ed25519PrivToScalar(signerPriv)
	if err != nil {
		return nil, err
	}

	n := len(ring)
	alpha, err := randomScalar()
	if err != nil {
		return nil, err
	}

	c := make([]*edwards25519.Scalar, n)
	r := make([]*edwards25519.Scalar, n)

	// Start at signerIdx: L_k = alpha * B
	Lk := new(edwards25519.Point).ScalarBaseMult(alpha)
	next := (signerIdx + 1) % n
	c[next], err = hashChallenge(msg, ringBytes, Lk)
	if err != nil {
		return nil, err
	}

	// Simulate remaining ring members from signerIdx+1 around to signerIdx.
	for step := 1; step < n; step++ {
		i := (signerIdx + step) % n
		ri, err := randomScalar()
		if err != nil {
			return nil, err
		}
		r[i] = ri

		// L_i = r_i * B + c_i * P_i
		rB := new(edwards25519.Point).ScalarBaseMult(ri)
		cP := new(edwards25519.Point).ScalarMult(c[i], pts[i])
		Li := new(edwards25519.Point).Add(rB, cP)

		nextIdx := (i + 1) % n
		c[nextIdx], err = hashChallenge(msg, ringBytes, Li)
		if err != nil {
			return nil, err
		}
	}

	// Close the ring at signerIdx: r_k = alpha - c_k * x (mod l)
	cx := new(edwards25519.Scalar).Multiply(c[signerIdx], x)
	r[signerIdx] = new(edwards25519.Scalar).Subtract(alpha, cx)

	rStrings := make([]string, n)
	for i := 0; i < n; i++ {
		rStrings[i] = base64.StdEncoding.EncodeToString(r[i].Bytes())
	}

	return &RingSignature{
		C0: base64.StdEncoding.EncodeToString(c[0].Bytes()),
		R:  rStrings,
	}, nil
}

// VerifyRing verifies a 1-out-of-N Schnorr ring signature against msg and ring.
func VerifyRing(msg []byte, ring []ed25519.PublicKey, sig *RingSignature) bool {
	if sig == nil || len(sig.R) != len(ring) || len(ring) == 0 {
		return false
	}
	pts, ringBytes, err := encodeRingPoints(ring)
	if err != nil {
		return false
	}

	c0Bytes, err := base64.StdEncoding.DecodeString(sig.C0)
	if err != nil || len(c0Bytes) != 32 {
		return false
	}
	cCur, err := new(edwards25519.Scalar).SetCanonicalBytes(c0Bytes)
	if err != nil {
		return false
	}

	for i := 0; i < len(ring); i++ {
		rBytes, err := base64.StdEncoding.DecodeString(sig.R[i])
		if err != nil || len(rBytes) != 32 {
			return false
		}
		ri, err := new(edwards25519.Scalar).SetCanonicalBytes(rBytes)
		if err != nil {
			return false
		}

		rB := new(edwards25519.Point).ScalarBaseMult(ri)
		cP := new(edwards25519.Point).ScalarMult(cCur, pts[i])
		Li := new(edwards25519.Point).Add(rB, cP)

		cCur, err = hashChallenge(msg, ringBytes, Li)
		if err != nil {
			return false
		}
	}

	return subtle.ConstantTimeCompare(cCur.Bytes(), c0Bytes) == 1
}
