# Cryptonite-go

Minimal, dependency-free cryptography library in Go implemented using only the standard library.

Goal: provide clear, reproducible, and easily testable implementations of contemporary algorithms behind small, composable interfaces without importing anything beyond Go's stdlib.


## Features

- Stdlib-only: no third-party packages.
- Uniform AEAD API via `Aead` (`Encrypt`/`Decrypt`).
- Hash/XOF helpers under `hash/xoodyak` (`New`, `NewXOF`).
- KDF helpers under `kdf` (HKDF-SHA256, PBKDF2-HMAC-SHA1/SHA256).
- Signature and key-agreement wrappers under `sig/ed25519` and `ecdh/p256`.
- Authentication tag layout is always `ciphertext || tag`.
- Known Answer Tests (KAT) in `test/aead/testdata`, `test/hash/testdata`, `test/kdf/testdata`, and curated signature/ECDH vectors.
- Readable, self-contained code; selective zeroization of sensitive buffers.


## Supported algorithms

**AEAD**
- ASCON-128a (`aead.NewAscon128()`): Key 16B, Nonce 16B, Tag 16B
- Xoodyak-Encrypt (`aead.NewXoodyak()`): Key 16B, Nonce 16B, Tag 16B
- ChaCha20-Poly1305 (`aead.NewChaCha20Poly1305()`): Key 32B, Nonce 12B, Tag 16B
- AES-GCM (`aead.NewAESGCM()`): Key 16/24/32B, Nonce 12B, Tag 16B
- XChaCha20-Poly1305 (`aead.NewXChaCha20Poly1305()`): Key 32B, Nonce 24B, Tag 16B (via HChaCha20)
<!-- - AES-128/256-SIV (`aead.NewAES128SIV()`, `aead.NewAES256SIV()`): deterministic IV (placeholder, implementation pending)
- AES-GCM-SIV (`aead.NewAESGCMSIV()`): nonce-misuse resistant GCM variant (placeholder)
- Deoxys-II-128 (`aead.NewDeoxysII128()`): NIST LwC finalist (placeholder) -->

**Hash / XOF**
- Xoodyak Hash (32-byte digest) via `hash/xoodyak.New()`
- Xoodyak XOF (arbitrary length) via `hash/xoodyak.NewXOF()`

**KDF**
- HKDF-SHA256 (`kdf.HKDFSHA256`, `HKDFSHA256Extract`, `HKDFSHA256Expand`)
- PBKDF2-HMAC-SHA1 / PBKDF2-HMAC-SHA256 (`kdf.PBKDF2SHA1`, `kdf.PBKDF2SHA256`)

**Signatures**
- Ed25519 wrappers (`sig/ed25519`): key generation, deterministic keys, sign/verify

**Key exchange**
- ECDH P-256 wrappers (`ecdh/p256`): deterministic/private key helpers and shared-secret computation


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


## Examples

Local import paths (as used in tests):
- `cryptonite-go/aead`
- `cryptonite-go/hash/xoodyak`
- `cryptonite-go/kdf`
- `cryptonite-go/sig/ed25519`
- `cryptonite-go/ecdh/p256`

ASCON-128a
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
    ad := []byte("header")
    pt := []byte("hello ascon")

    ct, err := a.Encrypt(key, nonce, ad, pt)
    if err != nil { panic(err) }

    dec, err := a.Decrypt(key, nonce, ad, ct)
    if err != nil { panic(err) }

    fmt.Println(string(dec)) // "hello ascon"
}
```

ChaCha20-Poly1305
```go
package main

import (
    "cryptonite-go/aead"
)

func main() {
    a := aead.NewChaCha20Poly1305()
    key := make([]byte, 32)   // 32 bytes
    nonce := make([]byte, 12) // 12 bytes
    ct, _ := a.Encrypt(key, nonce, nil, []byte("msg"))
    _, _ = a.Decrypt(key, nonce, nil, ct)
}
```

Xoodyak-Encrypt
```go
package main

import (
    "cryptonite-go/aead"
)

func main() {
    a := aead.NewXoodyak()
    key := make([]byte, 16)   // 16 bytes
    nonce := make([]byte, 16) // 16 bytes
    ct, _ := a.Encrypt(key, nonce, nil, []byte("msg"))
    _, _ = a.Decrypt(key, nonce, nil, ct)
}
```

XChaCha20-Poly1305 (24-byte nonce)
```go
package main

import (
    "cryptonite-go/aead"
)

func main() {
    a := aead.NewXChaCha20Poly1305()
    key := make([]byte, 32)
    nonce := make([]byte, 24)
    ct, _ := a.Encrypt(key, nonce, nil, []byte("msg"))
    _, _ = a.Decrypt(key, nonce, nil, ct)
}
```

Xoodyak Hash / XOF
```go
package main

import (
    "fmt"
    xoohash "cryptonite-go/hash/xoodyak"
)

func main() {
    h := xoohash.New()
    h.Write([]byte("abc"))
    fmt.Printf("%x\n", h.Sum(nil))

    xof := xoohash.NewXOF()
    xof.Write([]byte("abc"))
    buf := make([]byte, 64)
    xof.Read(buf)
    fmt.Printf("%x\n", buf)
}
```

HKDF / PBKDF2
```go
package main

import (
    "fmt"
    "cryptonite-go/kdf"
)

func main() {
    secret := []byte("input keying material")
    salt := []byte("salt")
    info := []byte("context")
    okm, _ := kdf.HKDFSHA256(secret, salt, info, 32)
    fmt.Printf("HKDF: %x\n", okm)

    password := []byte("password")
    derived, _ := kdf.PBKDF2SHA256(password, salt, 100000, 32)
    fmt.Printf("PBKDF2: %x\n", derived)
}
```

Ed25519 / ECDH P-256
```go
package main

import (
    "bytes"
    "fmt"
    ecdhp256 "cryptonite-go/ecdh/p256"
    ed "cryptonite-go/sig/ed25519"
)

func main() {
    pub, priv, _ := ed.GenerateKey()
    msg := []byte("hello")
    sig := ed.Sign(priv, msg)
    fmt.Println("signature valid?", ed.Verify(pub, msg, sig))

    privA, _ := ecdhp256.GenerateKey()
    privB, _ := ecdhp256.GenerateKey()
    sharedA, _ := ecdhp256.SharedSecret(privA, privB.PublicKey())
    sharedB, _ := ecdhp256.SharedSecret(privB, privA.PublicKey())
    fmt.Println("shared secrets match?", bytes.Equal(sharedA, sharedB))
}
```


## Running tests

- All tests: `go test ./...`
- With race detector: `go test -race ./...`

Tests include KAT suites for ASCON, Xoodyak, and ChaCha20‑Poly1305, plus tamper checks on tags and ciphertext.


## Design principles

- Pure Go, stdlib‑only (e.g., `crypto/subtle`, `encoding/binary`, `math/bits`).
- Explicit and readable code; no hidden dependencies.
- Minimal, consistent API to ease composition and testing.
- Simple output layout: `ciphertext || tag` across implementations.


## Security and limitations

- This library has not undergone independent security audits. Do not use in production without a thorough review.
- Implementations aim to be constant-time where required (e.g., Poly1305 follows the upstream bit-sliced algorithm). Review and test before use in side-channel-sensitive environments.
- Algorithms require exact key/nonce sizes; invalid sizes result in errors.
- AES-SIV, AES-GCM-SIV, and Deoxys-II constructors are currently placeholders that return `not implemented` errors; they are listed to document the planned API.


## Roadmap (ideas)

- Elliptic curves and related primitives (ECDH/ECDSA, EdDSA) in pure Go.
- Streaming/incremental APIs where appropriate (buffered AD/PT processing).
- Reproducible benchmarks and performance profiles.
