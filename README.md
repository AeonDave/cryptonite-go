# Cryptonite-go

[![CodeQL Advanced](https://github.com/AeonDave/cryptonite-go/actions/workflows/codeql.yml/badge.svg)](https://github.com/AeonDave/cryptonite-go/actions/workflows/codeql.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/AeonDave/cryptonite-go)](https://goreportcard.com/report/github.com/AeonDave/cryptonite-go)
![GitHub License](https://img.shields.io/github/license/AeonDave/cryptonite-go)

Minimal, modern, dependency-free cryptography library for Go, using only the standard library.

## Overview
- Small and auditable: pure Go, no third-party dependencies, making code review and security inspections straightforward.
- Reduced attack surface: shared, well-tested internal primitives and minimal cross-package APIs.
- Consistent, ergonomic interfaces: uniform AEAD, hashing, KDF, signature, and ECDH APIs for easy composition.
- Practical security defaults: spec-aligned choices, selective zeroisation of sensitive buffers, and attention to constant-time behavior where required.
- Robust test coverage and regression protection: known-answer tests, Wycheproof-inspired suites, and fuzzing harnesses.
- Interoperability for real-world use: implements widely used constructions (HPKE, X25519, Ed25519, AES, ChaCha20-Poly1305, etc.) without exposing low-level implementation details.

## Requirements
- Go 1.22+

## Installation

```bash
go get github.com/AeonDave/cryptonite-go
```

## Supported algorithms

### AEAD

| Algorithm          | Constructor(s)                                 | Key         | Nonce               | Tag  | Notes                                                                            | RFC / Spec |
|--------------------|------------------------------------------------|-------------|---------------------|------|----------------------------------------------------------------------------------|------------|
| ASCON-128a         | `aead.NewAscon128()`                           | 16 B        | 16 B                | 16 B | NIST LwC winner                                                                  | [FIPS 208](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.208.pdf) |
| Xoodyak-Encrypt    | `aead.NewXoodyak()`                            | 16 B        | 16 B                | 16 B | Cyclist mode                                                                     | [Xoodyak specification](https://keccak.team/files/Xoodyak-specification.pdf) |
| ChaCha20-Poly1305  | `aead.NewChaCha20Poly1305()`                   | 32 B        | 12 B                | 16 B | RFC 8439 layout                                                                  | [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439.html) |
| XChaCha20-Poly1305 | `aead.NewXChaCha20Poly1305()`                  | 32 B        | 24 B                | 16 B | Derives nonce via HChaCha20                                                      | [draft-irtf-cfrg-xchacha-03](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03) |
| AES-GCM            | `aead.NewAESGCM()`                             | 16/24/32 B  | 12 B                | 16 B | AES-NI optional                                                                  | [NIST SP 800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf) |
| AES-GCM-SIV        | `aead.NewAesGcmSiv()`                          | 16/32 B     | 12 B                | 16 B | Nonce misuse resistant                                                           | [RFC 8452](https://www.rfc-editor.org/rfc/rfc8452.html) |
| AES-SIV (128/256)  | `aead.NewAES128SIV()`<br>`aead.NewAES256SIV()` | 32 B / 64 B | Deterministic (AAD) | 16 B | Deterministic SIV construction; optional multi-AD support via `aead.MultiAssociatedData` | [RFC 5297](https://www.rfc-editor.org/rfc/rfc5297.html) |
| Deoxys-II-256-128  | `aead.NewDeoxysII128()`                        | 32 B        | 15 B                | 16 B | NIST LwC finalist                                                                | [NIST LWC finalist spec](https://csrc.nist.gov/csrc/media/Projects/lightweight-cryptography/documents/finalists/deoxys-spec-final.pdf) |

### Hashing

Every hashing entry point lives under the `hash` package so callers can rely on the uniform `hash.Hasher` interface or the Go `hash.Hash` type without importing algorithm-specific subpackages.

| Algorithm    | Streaming constructor                          | Single-shot helper(s)                                   | Notes                    | RFC / Spec |
|--------------|------------------------------------------------|---------------------------------------------------------|---------------------------|------------|
| SHA3-224     | `hash.NewSHA3224()`                            | `hash.NewSHA3224Hasher()` / `hash.Sum224`               | 224-bit (28 B) digest | [FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) |
| SHA3-256     | `hash.NewSHA3256()`                            | `hash.NewSHA3256Hasher()` / `hash.Sum256`               | 256-bit (32 B) digest | [FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) |
| SHA3-384     | `hash.NewSHA3384()`                            | `hash.NewSHA3384Hasher()` / `hash.Sum384`               | 384-bit (48 B) digest | [FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) |
| SHA3-512     | `hash.NewSHA3512()`                            | `hash.NewSHA3512Hasher()` / `hash.Sum512`               | 512-bit (64 B) digest | [FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) |
| BLAKE2b      | `hash.NewBlake2b()` / `hash.NewBlake2bBuilder()` | `hash.NewBlake2bHasher()`                              | Configurable 1–64 B digest, optional keyed MAC mode | [RFC 7693](https://www.rfc-editor.org/rfc/rfc7693.html) |
| BLAKE2s      | `hash.NewBlake2s()` / `hash.NewBlake2sBuilder()` | `hash.NewBlake2sHasher()`                              | Configurable 1–32 B digest, optional keyed MAC mode | [RFC 7693](https://www.rfc-editor.org/rfc/rfc7693.html) |
| Xoodyak Hash | `hash.NewXoodyak()`                            | `hash.NewXoodyakHasher()` / `hash.SumXoodyak()`         | 32 B Cyclist hash     | [Xoodyak specification](https://keccak.team/files/Xoodyak-specification.pdf) |

#### SP 800-185 constructions

| Algorithm             | Helper(s)                                                                              | Notes                                 | RFC / Spec |
|-----------------------|----------------------------------------------------------------------------------------|----------------------------------------|------------|
| TupleHash128 / 256    | `hash.TupleHash128(tuple, outLen, customization)` / `hash.TupleHash256`                | Tuple of byte-strings, optional customization | [NIST SP 800-185](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf) |
| ParallelHash128 / 256 | `hash.ParallelHash128(msg, blockSize, outLen, customization)` / `hash.ParallelHash256` | Parallel-friendly hashing for large messages  | [NIST SP 800-185](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf) |

### XOF (Extendable-output function)

Constructors live under the dedicated `xof` package and return the shared `xof.XOF` interface so extendable-output primitives can be swapped transparently.

| Algorithm   | Constructor      | Notes                                      | RFC / Spec |
|-------------|------------------|--------------------------------------------|------------|
| SHAKE128    | `xof.SHAKE128()` | Arbitrary-length output (FIPS 202)         | [FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) |
| SHAKE256    | `xof.SHAKE256()` | Wider security margin, arbitrary output    | [FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) |
| BLAKE2b XOF | `xof.Blake2b()`  | Supports fixed-length and streaming output | [BLAKE2 XOF](https://www.blake2.net/blake2x.pdf) |
| BLAKE2s XOF | `xof.Blake2s()`  | Lightweight XOF with keyed support         | [BLAKE2 XOF](https://www.blake2.net/blake2x.pdf) |
| Xoodyak XOF | `xof.Xoodyak()`  | Cyclist extendable-output mode             | [Xoodyak specification](https://keccak.team/files/Xoodyak-specification.pdf) |

### KDF (Key derivation function)

| Algorithm           | Deriver constructor                                  | Single-shot helper(s)                                                   | Notes                                                         | RFC / Spec |
|---------------------|------------------------------------------------------|-------------------------------------------------------------------------|---------------------------------------------------------------|------------|
| HKDF-SHA256         | `kdf.NewHKDFSHA256()`                                | `kdf.HKDFSHA256()`<br>`kdf.HKDFSHA256Extract()`<br>`kdf.HKDFSHA256Expand()` | Max length 255 × 32 B (RFC 5869)                              | [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html) |
| HKDF (generic hash) | `kdf.NewHKDF(func() hash.Hash)`                      | `kdf.HKDF()`<br>`kdf.HKDFExtractWith()`<br>`kdf.HKDFExpandWith()`           | Length bound = 255 × hash.Size()                              | [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html) |
| HKDF-BLAKE2b        | `kdf.NewHKDFBlake2b()`                               | `kdf.HKDFBlake2b()`                                                     | 64 B digest variant                                           | [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html) |
| PBKDF2-SHA1         | `kdf.NewPBKDF2SHA1()`                                | `kdf.PBKDF2SHA1()`<br>`kdf.PBKDF2SHA1Into()`                               | See `kdf.CheckParams` for policy checks                       | [RFC 8018](https://www.rfc-editor.org/rfc/rfc8018.html) |
| PBKDF2-SHA256       | `kdf.NewPBKDF2SHA256()`                              | `kdf.PBKDF2SHA256()`<br>`kdf.PBKDF2SHA256Into()`                           | Iterations > 0; variable output length                        | [RFC 8018](https://www.rfc-editor.org/rfc/rfc8018.html) |
| Argon2id            | `kdf.NewArgon2id()`<br>`kdf.NewArgon2idWithParams()` | `kdf.Argon2id()`                                                         | RFC 9106 Argon2id; defaults to time=1, memory=64 MiB, lanes=1 | [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html) |
| scrypt              | `kdf.NewScrypt(n, r, p)`                             | `kdf.Scrypt()`                                                          | RFC 7914 constraints on n,r,p; variable output length         | [RFC 7914](https://www.rfc-editor.org/rfc/rfc7914.html) |

### MAC (Message authentication code)

| Algorithm   | Entry points                                                            | Key             | Tag  | Notes                       | RFC / Spec |
|-------------|-------------------------------------------------------------------------|-----------------|------|-----------------------------|------------|
| HMAC-SHA256 | `mac.Sum(key, data)`<br>`mac.Verify(key, data, tag)`                    | Any length      | 32 B | Single-shot helpers over SHA-256    | [RFC 2104](https://www.rfc-editor.org/rfc/rfc2104.html) |
| Poly1305    | `mac.NewPoly1305(key)`<br>`mac.SumPoly1305()`<br>`mac.VerifyPoly1305()` | 32 B (one-time) | 16 B | One-time key per message (RFC 7539) | [RFC 7539](https://www.rfc-editor.org/rfc/rfc7539.html) |

### Stream ciphers

`stream.NewChaCha20` and `stream.NewXChaCha20` expose the shared `stream.Stream` interface (with `Reset`, `KeyStream`, and `XORKeyStream`) so applications can swap keystream generators without touching call sites.

| Algorithm | Constructor             | Key  | Nonce | Notes                                       | RFC / Spec |
|-----------|-------------------------|------|-------|---------------------------------------------|------------|
| ChaCha20  | `stream.NewChaCha20()`  | 32 B | 12 B  | IETF variant with configurable counter      | [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439.html) |
| XChaCha20 | `stream.NewXChaCha20()` | 32 B | 24 B  | HChaCha20-derived subkeys and raw keystream | [draft-irtf-cfrg-xchacha-03](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03) |

### Block ciphers

Block primitives are instantiated through `block.NewAES128` / `block.NewAES256`, both returning the shared `block.Cipher` interface.

| Algorithm | Constructor         | Key  | Block | Notes                        | RFC / Spec |
|-----------|---------------------|------|-------|------------------------------|------------|
| AES-128   | `block.NewAES128()` | 16 B | 16 B  | Thin wrapper over stdlib AES | [FIPS 197](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf) |
| AES-256   | `block.NewAES256()` | 32 B | 16 B  | Thin wrapper over stdlib AES | [FIPS 197](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf) |

### Signatures (ECDSA, EdDSA)

| Algorithm   | Constructor(s)       | Public              | Private     | Signature            | Notes                                                  | RFC / Spec |
|-------------|----------------------|---------------------|-------------|----------------------|--------------------------------------------------------|------------|
| Ed25519     | `sig.NewEd25519()`   | 32 B                | 64 B        | 64 B                 | Deterministic; `sig.FromSeed(32 B)` supported          | [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html) |
| ECDSA P-256 | `sig.NewECDSAP256()` | 65 B (uncompressed) | 32 B scalar | ASN.1 DER (variable) | Helpers: `sig.GenerateKeyECDSAP256`, `sig.SignECDSAP256`, `sig.VerifyECDSAP256` | [FIPS 186-5](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf) |

| Algorithm | Constructor      | Public              | Private     | Shared | Notes                                   | RFC / Spec |
|-----------|------------------|---------------------|-------------|--------|-----------------------------------------|------------|
| X25519    | `ecdh.New()`     | 32 B                | 32 B        | 32 B   | RFC 7748 (crypto/ecdh)                  | [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748.html) |
| P-256     | `ecdh.NewP256()` | 65 B (uncompressed) | 32 B scalar | 32 B   | Uncompressed public: 0x04 \|\| X \|\| Y | [FIPS 186-5](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf) |
| P-384     | `ecdh.NewP384()` | 97 B (uncompressed) | 48 B scalar | 48 B   | Uncompressed public: 0x04 \|\| X \|\| Y | [FIPS 186-5](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf) |

### Post-quantum key encapsulation

The `kem` package defines a shared `kem.KEM` interface together with a deployable
hybrid construction:

* `kem.New()` - classical KEM adapter built on top of the existing
  `ecdh` helpers (deployable today, pure Go, stdlib only). The adapter lives in
  the `kem` package to highlight that it provides classical security and can be
  reused by non-PQ code paths.
* `pq.NewHybridX25519()` - versioned hybrid format that composes the X25519
  exchange with an optional ML-KEM component. Callers can inject a vetted ML-KEM
  implementation via `pq.NewHybrid(classical, mlkem)` without changing encoded
  formats or downstream APIs.

Key material and ciphertexts produced by the hybrid construction are encoded as
`version || len(classical) || classical || len(pq) || pq`, providing forwards
compatibility when the PQ component is introduced.

To encrypt payloads, the package also includes the convenience `pq.Seal` and
`pq.Open` helpers which perform the standard `KEM → HKDF → AEAD` flow. The
envelope format embeds the encapsulated key (length-prefixed), a key-schedule
identifier, and the AEAD ciphertext so that the receiver can deterministically
reproduce the derived key/nonce pair. The key schedule currently covers modern
AEADs such as ChaCha20-Poly1305, AES-256-GCM, AES-GCM-SIV, XChaCha20-Poly1305,
ASCON-128a, Deoxys-II-256-128, and the AES-SIV family.

Symmetric protection remains classical (AEAD); only the key agreement layer is
made hybrid/PQ-ready following the recommendations from
[draft-ietf-tls-hybrid-design](https://datatracker.ietf.org/doc/html/draft-ietf-tls-hybrid-design-05).

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
- SHA-3 and Xoodyak helpers under `hash` expose both streaming constructors (e.g. `hash.NewSHA3256()`, `hash.NewXoodyak()`) and
  single-shot helpers (`hash.NewSHA3256Hasher()`, `hash.NewXoodyakHasher()`, `hash.Sum*`, `hash.SumXoodyak`) that satisfy
  `hash.Hasher`.

KEM interface in `kem/kem.go`:

```go
type KEM interface {
        GenerateKey() (public, private []byte, err error)
        Encapsulate(public []byte) (ciphertext, sharedSecret []byte, err error)
        Decapsulate(private []byte, ciphertext []byte) ([]byte, error)
}
```

- `GenerateKey` derives a deterministic public key from freshly generated private key material using `crypto/rand` internally.
- `Encapsulate` produces a ciphertext and shared secret for the provided public key.
- `Decapsulate` recovers the shared secret from the ciphertext and recipient private key.

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

### Secret material helpers

```go
key := secret.SymmetricKeyFrom([]byte("\x01"))
defer key.Destroy()

nonce := secret.NewNonce(12)
defer nonce.Destroy()

ctr, _ := secret.NewCounter96(make([]byte, 12))
n0, _ := ctr.Next()
n1, _ := ctr.Next()
fmt.Printf("nonce0=%x nonce1=%x\n", n0, n1)
```

### HPKE (base mode)

```go
suite := hpke.SuiteX25519ChaCha20
pkR, skR, _ := hpke.GenerateKeyPair(rand.Reader, suite)

info := []byte("hpke demo")
enc, sender, _ := hpke.SetupBaseSender(rand.Reader, suite, pkR, info)
ciphertext, _ := sender.Seal([]byte("aad"), []byte("secret"))

receiver, _ := hpke.SetupBaseReceiver(suite, enc, skR, info)
plaintext, _ := receiver.Open([]byte("aad"), ciphertext)
fmt.Println(string(plaintext))
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
