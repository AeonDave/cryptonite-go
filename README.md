# Cryptonite-go

[![CodeQL Advanced](https://github.com/AeonDave/cryptonite-go/actions/workflows/codeql.yml/badge.svg)](https://github.com/AeonDave/cryptonite-go/actions/workflows/codeql.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/AeonDave/cryptonite-go)](https://goreportcard.com/report/github.com/AeonDave/cryptonite-go)
![GitHub License](https://img.shields.io/github/license/AeonDave/cryptonite-go)

Minimal, dependency-free cryptography library in Go implemented using only the standard library.

Goal: provide clear, reproducible, and easily testable implementations of contemporary algorithms behind small, composable interfaces without importing anything beyond Go's stdlib.


## Features

- Pure Go, stdlib-only implementations with no third-party dependencies.
- Shared internal primitives (Keccak sponge, Xoodoo permutation, AES, etc.) reused across packages to minimise the attack surface.
- Consistent AEAD and hashing APIs, including single-shot helpers via `hash.Hasher`, plus reusable KDF, signature, and ECDH layers.
- Extensive known-answer tests, spec-aligned constants (e.g. NIST FIPS 202 for SHA-3/SHAKE), and selective zeroisation of sensitive buffers.
- Uniform ciphertext layout for AEAD constructions (`ciphertext || tag`) and deterministic test fixtures for reproducibility.
- AES-SIV exposes optional multi-associated-data helpers so callers can supply the full vector of strings defined by RFC 5297.


## Supported algorithms

### AEAD

| Algorithm          | Constructor(s)                                 | Key         | Nonce               | Tag  | Notes                          |
|--------------------|------------------------------------------------|-------------|---------------------|------|--------------------------------|
| ASCON-128a         | `aead.NewAscon128()`                           | 16 B        | 16 B                | 16 B | NIST LwC winner                |
| Xoodyak-Encrypt    | `aead.NewXoodyak()`                            | 16 B        | 16 B                | 16 B | Cyclist mode                   |
| ChaCha20-Poly1305  | `aead.NewChaCha20Poly1305()`                   | 32 B        | 12 B                | 16 B | RFC 8439 layout                |
| XChaCha20-Poly1305 | `aead.NewXChaCha20Poly1305()`                  | 32 B        | 24 B                | 16 B | Derives nonce via HChaCha20    |
| AES-GCM            | `aead.NewAESGCM()`                             | 16/24/32 B  | 12 B                | 16 B | AES-NI optional                |
| AES-GCM-SIV        | `aead.NewAesGcmSiv()`                          | 16/32 B     | 12 B                | 16 B | Nonce misuse resistant         |
| AES-SIV (128/256)  | `aead.NewAES128SIV()`<br>`aead.NewAES256SIV()` | 32 B / 64 B | Deterministic (AAD) | 16 B | Deterministic SIV construction; optional multi-AD support via `aead.MultiAssociatedData` |
| Deoxys-II-256-128  | `aead.NewDeoxysII128()`                        | 32 B        | 15 B                | 16 B | NIST LwC finalist              |

### Hashing

| Algorithm    | Streaming constructor | Single-shot helper(s)                     | Output                |
|--------------|-----------------------|-------------------------------------------|-----------------------|
| SHA3-224     | `sha3.Newsha3224()`   | `sha3.Newsha3224Hasher()` / `sha3.Sum224` | 224-bit (28 B) digest |
| SHA3-256     | `sha3.Newsha3256()`   | `sha3.Newsha3256Hasher()` / `sha3.Sum256` | 256-bit (32 B) digest |
| SHA3-384     | `sha3.Newsha3384()`   | `sha3.Newsha3384Hasher()` / `sha3.Sum384` | 384-bit (48 B) digest |
| SHA3-512     | `sha3.Newsha3512()`   | `sha3.Newsha3512Hasher()` / `sha3.Sum512` | 512-bit (64 B) digest |
| BLAKE2b      | `hash.NewBlake2bBuilder()` | `hash.NewBlake2bHasher()` / `hash.NewBlake2b` | Configurable 1–64 B digest, optional keyed mode |
| BLAKE2s      | `hash.NewBlake2sBuilder()` | `hash.NewBlake2sHasher()` / `hash.NewBlake2s` | Configurable 1–32 B digest, optional keyed mode |
| Xoodyak Hash | `xoodyak.New()`       | `xoodyak.NewHasher()` / `xoodyak.Sum`     | 32 B digest           |

### XOF

| Algorithm   | Constructor           | Notes                                   |
|-------------|-----------------------|-----------------------------------------|
| SHAKE128        | `shake.NewSHAKE128()`         | Arbitrary-length output (FIPS 202)      |
| SHAKE256        | `shake.NewSHAKE256()`         | Wider security margin, arbitrary output |
| BLAKE2b XOF     | `hash.NewBlake2bXOF()`        | Supports fixed-length and streaming output |
| BLAKE2s XOF     | `hash.NewBlake2sXOF()`        | Lightweight XOF with keyed support       |
| Xoodyak XOF     | `xoodyak.NewXOF()`            | Cyclist extendable-output mode          |

### KDF

- HKDF-SHA256 (`kdf.HKDFSHA256`, `kdf.HKDFSHA256Extract`, `kdf.HKDFSHA256Expand`)
- Generic HKDF helpers (`kdf.HKDF`, `kdf.HKDFExtractWith`, `kdf.HKDFExpandWith`, `kdf.NewHKDF`)
- HKDF-BLAKE2b (`kdf.HKDFBlake2b`, `kdf.NewHKDFBlake2b`)
- PBKDF2-HMAC-SHA1 / PBKDF2-HMAC-SHA256 (`kdf.PBKDF2SHA1`, `kdf.PBKDF2SHA256`, `kdf.PBKDF2SHA1Into`, `kdf.PBKDF2SHA256Into`, `kdf.CheckParams`)

### MAC

- HMAC-SHA256 (`mac/hmacsha256.Sum`, `mac/hmacsha256.Verify`)

### Signatures

- EdDSA on Curve25519 (`sig/x25519`): deterministic seeds, sign/verify helpers, and top-level aliases under `sig`
- ECDSA P-256 (`sig/p256`): scalar import/export, ASN.1 helpers, deterministic KAT coverage

### Key exchange

- X25519 Diffie-Hellman (`ecdh/x25519`): RFC 7748 scalar helpers and shared-secret computation
- ECDH P-256 (`ecdh/p256`): deterministic/private key helpers and shared-secret computation
- ECDH P-384 (`ecdh/p384`): high-strength NIST curve support with deterministic testing vectors


## Requirements

- Go 1.22+


## API

Common interface in `aead/aead.go`:

```go
type Aead interface {
    Encrypt(key, nonce, ad, plaintext []byte) ([]byte, error)
    Decrypt(key, nonce, ad, ciphertextAndTag []byte) ([]byte, error)
}
```

- `Encrypt` returns `ciphertext||tag` (16‑byte tag appended).
- `Decrypt` verifies the tag in constant‑time where possible and returns the plaintext or an error.

Hash helper interface in `hash/hash.go`:

```go
type Hasher interface {
    Hash(msg []byte) []byte
    Size() int
}
```

- `Hash` computes the digest of the provided message using any of the available primitives.
- `Size` reports the fixed digest length (in bytes).
- SHA-3 and Xoodyak packages expose both streaming constructors (e.g. `sha3.Newsha3256()`, `xoodyak.New()`) and single-shot helpers (`sha3.Newsha3256Hasher()`, `xoodyak.NewHasher()`, `sha3.Sum*`, `xoodyak.Sum`) that satisfy `hash.Hasher`.


## Examples

The packages are imported using the module path prefix (`cryptonite-go/...`). Below are two representative snippets; see the package documentation for more variants.

### AEAD (ASCON-128a)

```go
package main

import (
    "fmt"
    "cryptonite-go/aead"
)

func main() {
    a := aead.NewAscon128()
    key := make([]byte, 16)   // 16 bytes
    nonce := make([]byte, 16) // 16 bytes
    ct, err := a.Encrypt(key, nonce, []byte("header"), []byte("hello ascon"))
    if err != nil {
        panic(err)
    }
    pt, err := a.Decrypt(key, nonce, []byte("header"), ct)
    if err != nil {
        panic(err)
    }
    fmt.Println(string(pt))
}
```

### Hashing (SHA3-256 single-shot)

```go
package main

import (
    "fmt"
    "cryptonite-go/hash/sha3"
)

func main() {
    hasher := sha3.Newsha3256Hasher()
    digest := hasher.Hash([]byte("hello sha3"))
    fmt.Printf("%x\n", digest)
}
```


## Running tests

- All tests: `go test ./...`
- With race detector: `go test -race ./...`

Tests include KAT suites for ASCON, Xoodyak, ChaCha20‑Poly1305, AES-GCM-SIV, and AES-SIV (RFC 5297), plus tamper checks on tags and ciphertext.


## Design principles

- Pure Go, stdlib‑only (e.g., `crypto/subtle`, `encoding/binary`, `math/bits`).
- Explicit and readable code; no hidden dependencies.
- Minimal, consistent API to ease composition and testing.
- Simple output layout: `ciphertext || tag` across implementations.


## Security and limitations

- This library has not undergone independent security audits. Do not use in production without a thorough review.
- Implementations aim to be constant-time where required (e.g., Poly1305 follows the upstream bit-sliced algorithm). Review and test before use in side-channel-sensitive environments.
- Algorithms require exact key/nonce sizes; invalid sizes result in errors.
- Deoxys-II produces deterministic keystream inputs and is nonce-misuse resistant, but nonces must remain unique per key to avoid revealing repeated plaintext keystream correlations.
