# Cryptonite-go

[![CodeQL Advanced](https://github.com/AeonDave/cryptonite-go/actions/workflows/codeql.yml/badge.svg)](https://github.com/AeonDave/cryptonite-go/actions/workflows/codeql.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/AeonDave/cryptonite-go)](https://goreportcard.com/report/github.com/AeonDave/cryptonite-go)
![GitHub License](https://img.shields.io/github/license/AeonDave/cryptonite-go)

Minimal, dependency-free cryptography library in Go implemented using only the standard library.

- Pure Go, stdlib-only implementations with no third-party dependencies.
- Shared internal primitives (Keccak sponge, Xoodoo permutation, AES, etc.) reused across packages to minimise the
  attack surface.
- Consistent AEAD and hashing APIs, including single-shot helpers via `hash.Hasher`, plus reusable KDF, signature, and
  ECDH layers.
- Extensive known-answer tests, spec-aligned constants (e.g. NIST FIPS 202 for SHA-3/SHAKE), and selective zeroisation
  of sensitive buffers.
- Uniform ciphertext layout for AEAD constructions (`ciphertext || tag`) and deterministic test fixtures for
  reproducibility.
- AES-SIV exposes optional multi-associated-data helpers so callers can supply the full vector of strings defined by RFC
  5297.

## Requirements

- Go 1.22+

## Installation

```bash
go get github.com/AeonDave/cryptonite-go
```

## Supported algorithms

### AEAD

| Algorithm          | Constructor(s)                                 | Key         | Nonce               | Tag  | Notes                                                                                    |
|--------------------|------------------------------------------------|-------------|---------------------|------|------------------------------------------------------------------------------------------|
| ASCON-128a         | `aead.NewAscon128()`                           | 16 B        | 16 B                | 16 B | NIST LwC winner                                                                          |
| Xoodyak-Encrypt    | `aead.NewXoodyak()`                            | 16 B        | 16 B                | 16 B | Cyclist mode                                                                             |
| ChaCha20-Poly1305  | `aead.NewChaCha20Poly1305()`                   | 32 B        | 12 B                | 16 B | RFC 8439 layout                                                                          |
| XChaCha20-Poly1305 | `aead.NewXChaCha20Poly1305()`                  | 32 B        | 24 B                | 16 B | Derives nonce via HChaCha20                                                              |
| AES-GCM            | `aead.NewAESGCM()`                             | 16/24/32 B  | 12 B                | 16 B | AES-NI optional                                                                          |
| AES-GCM-SIV        | `aead.NewAesGcmSiv()`                          | 16/32 B     | 12 B                | 16 B | Nonce misuse resistant                                                                   |
| AES-SIV (128/256)  | `aead.NewAES128SIV()`<br>`aead.NewAES256SIV()` | 32 B / 64 B | Deterministic (AAD) | 16 B | Deterministic SIV construction; optional multi-AD support via `aead.MultiAssociatedData` |
| Deoxys-II-256-128  | `aead.NewDeoxysII128()`                        | 32 B        | 15 B                | 16 B | NIST LwC finalist                                                                        |

### Hashing

Every hashing entry point lives under the `hash` package so callers can rely on the uniform `hash.Hasher` interface or
the Go `hash.Hash` type without importing algorithm-specific subpackages.

| Algorithm    | Streaming constructor      | Single-shot helper(s)                           | Notes                                               |
|--------------|----------------------------|-------------------------------------------------|-----------------------------------------------------|
| SHA3-224     | `hash.NewSHA3224()`        | `hash.NewSHA3224Hasher()` / `hash.Sum224`       | 224-bit (28 B) digest                               |
| SHA3-256     | `hash.NewSHA3256()`        | `hash.NewSHA3256Hasher()` / `hash.Sum256`       | 256-bit (32 B) digest                               |
| SHA3-384     | `hash.NewSHA3384()`        | `hash.NewSHA3384Hasher()` / `hash.Sum384`       | 384-bit (48 B) digest                               |
| SHA3-512     | `hash.NewSHA3512()`        | `hash.NewSHA3512Hasher()` / `hash.Sum512`       | 512-bit (64 B) digest                               |
| BLAKE2b      | `hash.NewBlake2bBuilder()` | `hash.NewBlake2bHasher()` / `hash.NewBlake2b()` | Configurable 1–64 B digest, optional keyed MAC mode |
| BLAKE2s      | `hash.NewBlake2sBuilder()` | `hash.NewBlake2sHasher()` / `hash.NewBlake2s()` | Configurable 1–32 B digest, optional keyed MAC mode |
| Xoodyak Hash | `hash.NewXoodyak()`        | `hash.NewXoodyakHasher()` / `hash.SumXoodyak()` | 32 B Cyclist hash                                   |

### XOF (Extendable-output function)

Constructors live under the dedicated `xof` package and return the shared `xof.XOF` interface so extendable-output
primitives can be swapped transparently.

| Algorithm   | Constructor      | Notes                                      |
|-------------|------------------|--------------------------------------------|
| SHAKE128    | `xof.SHAKE128()` | Arbitrary-length output (FIPS 202)         |
| SHAKE256    | `xof.SHAKE256()` | Wider security margin, arbitrary output    |
| BLAKE2b XOF | `xof.Blake2b()`  | Supports fixed-length and streaming output |
| BLAKE2s XOF | `xof.Blake2s()`  | Lightweight XOF with keyed support         |
| Xoodyak XOF | `xof.Xoodyak()`  | Cyclist extendable-output mode             |

### KDF (Key derivation function)

| Algorithm           | Deriver constructor             | Single-shot helper(s)                                                       | Notes                                                 |
|---------------------|---------------------------------|-----------------------------------------------------------------------------|-------------------------------------------------------|
| HKDF-SHA256         | `kdf.NewHKDFSHA256()`           | `kdf.HKDFSHA256()`<br>`kdf.HKDFSHA256Extract()`<br>`kdf.HKDFSHA256Expand()` | Max length 255·32 B (RFC 5869)                        |
| HKDF (generic hash) | `kdf.NewHKDF(func() hash.Hash)` | `kdf.HKDF()`<br>`kdf.HKDFExtractWith()`<br>`kdf.HKDFExpandWith()`           | Length bound = 255·hash.Size()                        |
| HKDF-BLAKE2b        | `kdf.NewHKDFBlake2b()`          | `kdf.HKDFBlake2b()`                                                         | 64 B digest variant                                   |
| PBKDF2-SHA1         | `kdf.NewPBKDF2SHA1()`           | `kdf.PBKDF2SHA1()`<br>`kdf.PBKDF2SHA1Into()`                                | See `kdf.CheckParams` for policy checks               |
| PBKDF2-SHA256       | `kdf.NewPBKDF2SHA256()`         | `kdf.PBKDF2SHA256()`<br>`kdf.PBKDF2SHA256Into()`                            | Iterations > 0; variable output length                |
| scrypt              | `kdf.NewScrypt(n, r, p)`        | `kdf.Scrypt()`                                                              | RFC 7914 constraints on n,r,p; variable output length |

### MAC (Message authentication code)

| Algorithm   | Entry points                                                            | Key             | Tag  | Notes                               |
|-------------|-------------------------------------------------------------------------|-----------------|------|-------------------------------------|
| HMAC-SHA256 | `mac.Sum(key, data)`<br>`mac.Verify(key, data, tag)`                    | Any length      | 32 B | Single-shot helpers over SHA-256    |
| Poly1305    | `mac.NewPoly1305(key)`<br>`mac.SumPoly1305()`<br>`mac.VerifyPoly1305()` | 32 B (one-time) | 16 B | One-time key per message (RFC 7539) |

### Stream ciphers

`stream.NewChaCha20` and `stream.NewXChaCha20` expose the shared `stream.Stream` interface (with `Reset`, `KeyStream`,
and `XORKeyStream`) so applications can swap keystream generators without touching call sites.

| Algorithm | Constructor             | Key  | Nonce | Notes                                       |
|-----------|-------------------------|------|-------|---------------------------------------------|
| ChaCha20  | `stream.NewChaCha20()`  | 32 B | 12 B  | IETF variant with configurable counter      |
| XChaCha20 | `stream.NewXChaCha20()` | 32 B | 24 B  | HChaCha20-derived subkeys and raw keystream |

### Block ciphers

Block primitives are instantiated through `block.NewAES128` / `block.NewAES256`, both returning the shared
`block.Cipher` interface.

| Algorithm | Constructor         | Key  | Block | Notes                        |
|-----------|---------------------|------|-------|------------------------------|
| AES-128   | `block.NewAES128()` | 16 B | 16 B  | Thin wrapper over stdlib AES |
| AES-256   | `block.NewAES256()` | 32 B | 16 B  | Thin wrapper over stdlib AES |

### Signatures (ECDSA, EdDSA)

| Algorithm   | Constructor(s)            | Public              | Private     | Signature            | Notes |
|------------|----------------------------|---------------------|-------------|----------------------|-------|
| Ed25519    | `sig.NewEd25519()`         | 32 B                | 64 B        | 64 B                 | Deterministic; `sig.FromSeed(32 B)` supported |
| ECDSA P-256| `sig.NewECDSAP256()`       | 65 B (uncompressed) | 32 B scalar | ASN.1 DER (variable) | Helpers: `sig.GenerateKeyECDSAP256`, `sig.SignECDSAP256`, `sig.VerifyECDSAP256` |

| Algorithm | Constructor       | Public              | Private     | Shared | Notes |
|----------|-------------------|---------------------|-------------|--------|-------|
| X25519   | `ecdh.New()`      | 32 B                | 32 B        | 32 B   | RFC 7748 (crypto/ecdh) |
| P-256    | `ecdh.NewP256()`  | 65 B (uncompressed) | 32 B scalar | 32 B   | Uncompressed public: 0x04 || X || Y |
| P-384    | `ecdh.NewP384()`  | 97 B (uncompressed) | 48 B scalar | 48 B   | Uncompressed public: 0x04 || X || Y |

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
- SHA-3 and Xoodyak packages expose both streaming constructors (e.g. `sha3.Newsha3256()`, `xoodyak.New()`) and
  single-shot helpers (`sha3.Newsha3256Hasher()`, `xoodyak.NewHasher()`, `sha3.Sum*`, `xoodyak.Sum`) that satisfy
  `hash.Hasher`.

## Examples

The packages are imported using the module path prefix (`cryptonite-go/...`). Below are two representative snippets; see
the package documentation for more variants.

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

	"cryptonite-go/hash"
)

func main() {
	hasher := hash.NewSHA3256Hasher()
	digest := hasher.Hash([]byte("hello sha3"))
	fmt.Printf("%x\n", digest)
}
```

### XOF (SHAKE256)

```go
package main

import (
	"fmt"
	"cryptonite-go/xof"
)

func main() {
	x := xof.SHAKE256()
	x.Write([]byte("hello xof"))
	out := make([]byte, 32)
	x.Read(out)
	fmt.Printf("%x\n", out)
}
```

### KDF (HKDF-SHA256)

```go
package main

import (
	"fmt"
	"cryptonite-go/kdf"
)

func main() {
	d := kdf.NewHKDFSHA256()
	key, err := d.Derive(kdf.DeriveParams{
		Secret: []byte("ikm"),
		Salt:   []byte("salt"),
		Info:   []byte("ctx"),
		Length: 32,
	})
	if err != nil {
		panic(err)
	}
	fmt.Printf("%x\n", key)
}
```

### MAC (HMAC-SHA256)

```go
package main

import (
	"fmt"
	"cryptonite-go/mac"
)

func main() {
	key := []byte("hmac key")
	msg := []byte("data")
	tag := mac.Sum(key, msg)
	ok := mac.Verify(key, msg, tag)
	fmt.Println("ok:", ok)
}
```

### Stream (ChaCha20)

```go
package main

import (
	"fmt"
	"cryptonite-go/stream"
)

func main() {
	key := make([]byte, 32)
	nonce := make([]byte, 12)
	c, err := stream.NewChaCha20(key, nonce, 1)
	if err != nil {
		panic(err)
	}
	pt := []byte("hello chacha")
	ct := make([]byte, len(pt))
	c.XORKeyStream(ct, pt)
	c.Reset(1)
	recovered := make([]byte, len(ct))
	c.XORKeyStream(recovered, ct)
	fmt.Println(string(recovered))
}
```

### Block (AES-128)

```go
package main

import (
	"fmt"
	"cryptonite-go/block"
)

func main() {
	key := make([]byte, 16)
	c, err := block.NewAES128(key)
	if err != nil {
		panic(err)
	}
	src := []byte("0123456789abcdef") // 16 bytes
	dst := make([]byte, 16)
	c.Encrypt(dst, src)
	pt := make([]byte, 16)
	c.Decrypt(pt, dst)
	fmt.Println(string(pt))
}
```

### Signatures (Ed25519)

```go
package main

import (
	"fmt"
	"cryptonite-go/sig"
)

func main() {
	pub, priv, err := sig.GenerateKey()
	if err != nil {
		panic(err)
	}
	msg := []byte("hi ed25519")
	s := sig.Sign(priv, msg)
	ok := sig.Verify(pub, msg, s)
	fmt.Println("ok:", ok)
}
```

### Key exchange (X25519)

```go
package main

import (
	"fmt"
	"cryptonite-go/ecdh"
)

func main() {
	ke := ecdh.New() // X25519
	aPriv, _ := ke.GenerateKey()
	bPriv, _ := ke.GenerateKey()
	aShared, _ := ke.SharedSecret(aPriv, bPriv.PublicKey())
	bShared, _ := ke.SharedSecret(bPriv, aPriv.PublicKey())
	fmt.Println(string(aShared) == string(bShared))
}
```

## Running tests

- All tests: `go test ./...`
- With race detector: `go test -race ./...`

Tests include KAT suites for ASCON, Xoodyak, ChaCha20‑Poly1305, AES-GCM-SIV, and AES-SIV (RFC 5297), plus tamper checks
on tags and ciphertext.

## Design principles

- Pure Go, stdlib‑only (e.g., `crypto/subtle`, `encoding/binary`, `math/bits`).
- Explicit and readable code; no hidden dependencies.
- Minimal, consistent API to ease composition and testing.
- Simple output layout: `ciphertext || tag` across implementations.

## Security and limitations

- This library has not undergone independent security audits. Do not use in production without a thorough review.
- Implementations aim to be constant-time where required (e.g., Poly1305 follows the upstream bit-sliced algorithm).
  Review and test before use in side-channel-sensitive environments.
- Algorithms require exact key/nonce sizes; invalid sizes result in errors.
- Deoxys-II produces deterministic keystream inputs and is nonce-misuse resistant, but nonces must remain unique per key
  to avoid revealing repeated plaintext keystream correlations.



