# safeAuth

Zero-password, local-first authentication system in Go where your identity is rooted in a 128-bit BIP39 seed phrase and proven via Ed25519 challenge-response signatures—without the server ever storing passwords, emails, or PII.

## Architecture

- **128-bit Identity Root (`internal/identity`)**: Generates 16 bytes of cryptographic randomness (`crypto/rand`) encoded as a 12-word BIP39 mnemonic and derives a 64-byte master seed.
- **Per-Origin Key Isolation (`internal/identity`)**: Uses HKDF-SHA256 with `master_seed`, canonicalized service `origin`, `account_index`, and `epoch` to derive unlinkable Ed25519 keypairs per service, plus a separate root-derived recovery keypair.
- **Encrypted Local Vault (`internal/vault`)**: Stores the mnemonic, per-origin epoch state, and session tokens encrypted at rest using **Argon2id** + **XChaCha20-Poly1305** (`0600` permissions).
- **Challenge-Response Auth Server (`internal/server`)**:
  - Issues 32-byte random nonces with 60s TTL and atomic single-use consumption.
  - Timing/existence hardening: unknown account IDs still receive indistinguishable challenge responses, and `/verify` returns uniform `401` errors.
  - Per-IP token-bucket rate limiting (`429 Too Many Requests`).
  - Key rotation (`/rotate`) authorized by the root-derived recovery key, revoking compromised device keys.
  - Short-lived HMAC-SHA256 signed session tokens (`/session`).
- **Anonymous Allowlist Proof (`internal/zkring`)**: 1-out-of-N Schnorr ring signature over `edwards25519` (`/allowlist` + `/anon-verify`) proving membership in a service's authorized key set without revealing which account is authenticating.

## Quick Start

### 1. Run Tests
```powershell
go test -v ./...
```

### 2. Start the Auth Server
```powershell
go run ./cmd/safeauth-server -addr :8080 -origin localhost:8080
```

### 3. Use the Keyring CLI
```powershell
# Initialize encrypted local vault & generate 12-word BIP39 seed phrase
go run ./cmd/safeauth init

# Register derived public key & recovery key with server
go run ./cmd/safeauth register --server http://localhost:8080 --origin localhost:8080

# Login via Ed25519 challenge-response
go run ./cmd/safeauth login --server http://localhost:8080 --origin localhost:8080

# Verify session token
go run ./cmd/safeauth session --server http://localhost:8080 --origin localhost:8080

# Rotate compromised key to next epoch using root-derived recovery key
go run ./cmd/safeauth rotate --server http://localhost:8080 --origin localhost:8080

# Anonymous 1-out-of-N ring-signature login
go run ./cmd/safeauth anon-login --server http://localhost:8080 --origin localhost:8080
```
