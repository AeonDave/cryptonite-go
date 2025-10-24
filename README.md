# Cryptonite-go

[![CodeQL Advanced](https://github.com/AeonDave/cryptonite-go/actions/workflows/codeql.yml/badge.svg)](https://github.com/AeonDave/cryptonite-go/actions/workflows/codeql.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/AeonDave/cryptonite-go)](https://goreportcard.com/report/github.com/AeonDave/cryptonite-go)
![GitHub License](https://img.shields.io/github/license/AeonDave/cryptonite-go)

Modern, ultra-fast, zero-dependency cryptography library for Go 1.22+
Implemented using only the standard library. Battle-tested primitives, minimal attack surface, ergonomic APIs.

## Overview

- Small and auditable: pure Go, no third-party dependencies.
- Reduced attack surface: shared, tested internal primitives and minimal cross-package APIs.
- Consistent, ergonomic interfaces: uniform AEAD, hashing, KDF, signature, and ECDH APIs for easy composition.
- Practical security defaults: spec-aligned choices, selective zeroisation of sensitive buffers, constant-time behavior where required.
- Robust test coverage and regression protection: known-answer tests, Wycheproof-inspired suites, and fuzzing harnesses.
- Interoperability for real-world use: implements widely used constructions without exposing low-level implementation details.

## Requirements

- Go 1.22+

## Installation

```bash
go get github.com/AeonDave/cryptonite-go
```

## Supported Algorithms

### AEAD (Authenticated Encryption)
- **Mainstream**: AES-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305, AES-GCM-SIV
- **Lightweight**: ASCON-128a/80pq (NIST winner), Xoodyak, GIFT-COFB, SKINNY, Deoxys-II
- **Nonce-misuse resistant**: AES-SIV, AES-GCM-SIV

### Hashing & XOF
- **Fast**: BLAKE2b/s (742 MB/s), SHA-3 family
- **Streaming**: SHAKE128/256, BLAKE2 XOF, Xoodyak
- **Specialized**: TupleHash, ParallelHash (SP 800-185)

### Key Derivation (KDF)
- **Modern**: HKDF-SHA256/BLAKE2b, Argon2id, scrypt
- **Password**: PBKDF2-SHA1/SHA256

### MAC & Stream Ciphers
- **MAC**: HMAC-SHA256, Poly1305 (3+ GB/s)
- **Stream**: ChaCha20, XChaCha20, AES-CTR

### Public Key Crypto
- **Signatures**: Ed25519, ML-DSA-44/65/87 (Dilithium), ECDSA P-256
- **Key Exchange**: X25519, X448, ECDH P-256/P-384
- **Post-Quantum**: ML-DSA signatures + hybrid X25519+ML-KEM (via `pq` package)

Full algorithm matrix with specs:
See [docs/ALGORITHMS.md](docs/ALGORITHMS.md)

## API Quick Start

### Authenticated Encryption (ASCON-128a)

```go
package main

import (
    "fmt"
    "github.com/AeonDave/cryptonite-go/aead"
)

func main() {
    cipher := aead.NewAscon128()
    key := make([]byte, 16)
    nonce := make([]byte, 16)
    
    ciphertext, _ := cipher.Encrypt(key, nonce, []byte("header"), []byte("secret data"))
    plaintext, _ := cipher.Decrypt(key, nonce, []byte("header"), ciphertext)
    
    fmt.Println(string(plaintext)) // "secret data"
}
```

### Hashing (BLAKE2b)

```go
import "github.com/AeonDave/cryptonite-go/hash"

hasher := hash.NewBlake2bHasher()
digest := hasher.Hash([]byte("hello world"))
fmt.Printf("%x\n", digest)
```

### Key Exchange (X25519 / X448)

```go
import "github.com/AeonDave/cryptonite-go/ecdh"

x25519 := ecdh.NewX25519()
x448 := ecdh.NewX448()
alicePriv, _ := x25519.GenerateKey()
bobPriv, _ := x25519.GenerateKey()

aliceShared, _ := x25519.SharedSecret(alicePriv, bobPriv.PublicKey())
bobShared, _ := x25519.SharedSecret(bobPriv, alicePriv.PublicKey())
// aliceShared == bobShared

// X448 exposes the same API for higher security deployments.
alice448, _ := x448.GenerateKey()
bob448, _ := x448.GenerateKey()
shared448, _ := x448.SharedSecret(alice448, bob448.PublicKey())
```

### Digital Signatures (Ed25519)

```go
import "github.com/AeonDave/cryptonite-go/sig"

pub, priv, _ := sig.GenerateKey()
signature := sig.Sign(priv, []byte("message"))
valid := sig.Verify(pub, []byte("message"), signature)
```

### Post-Quantum Signatures (ML-DSA-44 / Dilithium-2)

```go
import "github.com/AeonDave/cryptonite-go/sig"

scheme := sig.NewMLDSA44()
pub, priv, _ := scheme.GenerateKey()
signature, _ := scheme.Sign(priv, []byte("message"))
valid := scheme.Verify(pub, []byte("message"), signature)
```

For deterministic signing (useful for KAT/interop), replace `sig.NewMLDSA44()` with `sig.NewDeterministicMLDSA44()` or
derive keys from a fixed 32-byte seed via `sig.GenerateDeterministicKeyMLDSA44(seed)`.

## Running tests

- All tests: `go test ./...`
- With race detector: `go test -race ./...`

Tests include KAT suites for ASCON, Xoodyak, ChaCha20‑Poly1305, AES-GCM-SIV, and AES-SIV (RFC 5297), plus tamper checks
on tags and ciphertext.

## Benchmarks

**Benchmark environment**: AMD Ryzen 7, Go 1.23, `-benchmem`

| Category | Algorithm | Throughput | Allocs/op | B/op |
|----------|-----------|------------|-----------|------|
| **AEAD** | AES-GCM (AES-NI) | 1488 MB/s | 0 | 0 |
| | ChaCha20-Poly1305 | 178 MB/s | 3 | 224 |
| | ASCON-128a ⭐ | 223 MB/s | 3 | 208 |
| **Hash** | BLAKE2b-512 | 742 MB/s | 2 | 128 |
| | SHA3-256 | 38 MB/s | 1 | 32 |
| **MAC** | Poly1305 | 3117 MB/s | 4 | 64 |
| **Stream** | ChaCha20 | 224 MB/s | 0 | 0 |
| **Sig** | Ed25519 Sign | 8 MB/s | 1 | 96 |
| | Ed25519 Verify | 23 MB/s | 0 | 0 |
| **ECDH** | X25519 | 0.82 MB/s | 1 | 64 |

**Highlights**:
- Zero allocations on hot paths (AES, ChaCha20, signature verify)
- Hardware acceleration (AES-NI) when available
- Competitive with specialized C libraries

These commands exercise the encryption/decryption, hashing, KDF, MAC, stream,
block, signature, ECDH, HPKE, post-quantum, and secret-management benchmarks
added alongside the existing test vectors.

Symmetric protection remains classical (AEAD); only the key agreement layer is
made hybrid/PQ-ready following the recommendations from
[draft-ietf-tls-hybrid-design](https://datatracker.ietf.org/doc/html/draft-ietf-tls-hybrid-design-05).

**Full benchmarks**: [benchmark.md](benchmark.md)
Run locally:

```bash
go test ./test/... -bench=. -benchmem
```
On Windows PowerShell, quote the empty test pattern with double quotes:

```powershell
go test ./test/... -run="^$" -bench . -benchmem -count=1
```

## Security

### Guarantees
- Constant-time operations where required (Poly1305, X25519, Ed25519)
- Automatic key/nonce zeroization via `secret` package helpers
- Wycheproof test vectors + fuzzing harnesses
- No CGO → reduced supply chain risk

### Limitations
- **This library has NOT been independently audited.** Even though it is deployed in production, perform thorough internal review and threat modeling before upgrading or integrating it into new systems.
- **Nonce management**: Caller responsible for uniqueness (use `secret.NewNonce()` or counters)
- **Side channels**: Best-effort mitigation; validate in your threat model
- **Algorithm selection**: Some primitives are experimental (e.g., GIFT-COFB) – prefer mainstream options (AES-GCM, ChaCha20) unless you need specific properties

### Reporting Issues
Security vulnerabilities: open a private advisory via GitHub.  
See [SECURITY.md](SECURITY.md) for full policy.

## Documentation

- **API Docs**: [pkg.go.dev/github.com/AeonDave/cryptonite-go](https://pkg.go.dev/github.com/AeonDave/cryptonite-go)
- **Guides**:
  - [Algorithm Matrix](docs/ALGORITHMS.md) – full specs & references
  - [Nonce Management](docs/NONCE_MANAGEMENT.md) – avoid reuse, counters, random generation
  - [HPKE Usage](docs/HPKE.md) – hybrid public key encryption
  - [Post-Quantum](docs/PQ.md) – hybrid X25519+ML-KEM guide
  - [Interoperability](docs/INTEROP.md) – wire formats, encodings, gotchas
- **Testing**: [docs/TESTING.md](docs/TESTING.md) – KAT, fuzzing, adding test vectors

## Contributing

Contributions welcome! Please:

1. **Run tests**: `go test -race ./...`
2. **Check formatting**: `go fmt ./...` + `golangci-lint run`
3. **Add vectors**: Include KAT for new algorithms (see [CONTRIBUTING.md](CONTRIBUTING.md))
4. **Benchmark**: `go test ./test/... -bench=YourFunc -benchmem`

See [CONTRIBUTING.md](CONTRIBUTING.md) for full guidelines.

## License

MIT – see [LICENSE](LICENSE)


**If you find this useful, star the repo!** | Questions? Open an [issue](https://github.com/AeonDave/cryptonite-go/issues).
