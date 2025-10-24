# Cryptonite-go

[![CodeQL Advanced](https://github.com/AeonDave/cryptonite-go/actions/workflows/codeql.yml/badge.svg)](https://github.com/AeonDave/cryptonite-go/actions/workflows/codeql.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/AeonDave/cryptonite-go)](https://goreportcard.com/report/github.com/AeonDave/cryptonite-go)
![GitHub License](https://img.shields.io/github/license/AeonDave/cryptonite-go)

Minimal, modern, ultra-fast, dependency-free cryptography go library, using only the standard library.

## Overview

- Small and auditable: pure Go, no third-party dependencies, making code review and security inspections
  straightforward.
- Reduced attack surface: shared, well-tested internal primitives and minimal cross-package APIs.
- Consistent, ergonomic interfaces: uniform AEAD, hashing, KDF, signature, and ECDH APIs for easy composition.
- Practical security defaults: spec-aligned choices, selective zeroisation of sensitive buffers, and attention to
  constant-time behavior where required.
- Robust test coverage and regression protection: known-answer tests, Wycheproof-inspired suites, and fuzzing harnesses.
- Interoperability for real-world use: implements widely used constructions (HPKE, X25519, Ed25519, AES,
  ChaCha20-Poly1305, etc.) without exposing low-level implementation details.

## Requirements

- Go 1.22+

## Installation

```bash
go get github.com/AeonDave/cryptonite-go
```

## Supported Algorithms

### AEAD (Authenticated Encryption)
- **Mainstream**: AES-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305, AES-GCM-SIV
- **Lightweight**: ASCON-128a/80pq ⭐ (NIST winner), Xoodyak, GIFT-COFB, SKINNY, Deoxys-II
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
- **Signatures**: Ed25519, ECDSA P-256
- **Key Exchange**: X25519, ECDH P-256/P-384
- **Post-Quantum**: Hybrid X25519+ML-KEM ready (via `pq` package)

<details>
<summary><b>📋 Full algorithm matrix with specs</b></summary>

See [docs/ALGORITHMS.md](docs/ALGORITHMS.md) for:
- Complete key/nonce/tag sizes
- RFC/FIPS references
- Interoperability notes
- Test vectors

</details>
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
- SHA-3 and Xoodyak helpers under `hash` expose both streaming constructors (e.g. `hash.NewSHA3256()`,
  `hash.NewXoodyak()`) and
  single-shot helpers (`hash.NewSHA3256Hasher()`, `hash.NewXoodyakHasher()`, `hash.Sum*`, `hash.SumXoodyak`) that
  satisfy
  `hash.Hasher`.

KEM interface in `kem/kem.go`:

```go
type KEM interface {
GenerateKey() (public, private []byte, err error)
Encapsulate(public []byte) (ciphertext, sharedSecret []byte, err error)
Decapsulate(private []byte, ciphertext []byte) ([]byte, error)
}
```

- `GenerateKey` derives a deterministic public key from freshly generated private key material using `crypto/rand`
  internally.
- `Encapsulate` produces a ciphertext and shared secret for the provided public key.
- `Decapsulate` recovers the shared secret from the ciphertext and recipient private key.

## Examples

The packages are imported using the module path prefix (`cryptonite-go/...`). Below are two representative snippets; see
the package documentation for more variants.

### AEAD (ASCON-128a / ASCON-80pq)

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

`aead.NewAscon80pq()` works identically but expects a 20-byte key and offers higher post-quantum security margins.

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
    ke := ecdh.NewX25519() // X25519
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

## Benchmarks

All algorithms in the repository ship with Go benchmark harnesses located under
the `test` directory. To gather benchmark numbers (including allocation
profiles) for every category, run:

Shell
```bash
go test ./test/... -bench=. -benchmem
```

Powershell
```bash
go test ./test/... -run='^$' -bench . -benchmem -count=1
```

You can scope the command to a specific family when needed, for example:

```bash
go test ./test/aead -bench=. -benchmem
go test ./test/hash -bench=. -benchmem
```

These commands exercise the encryption/decryption, hashing, KDF, MAC, stream,
block, signature, ECDH, HPKE, post-quantum, and secret-management benchmarks
added alongside the existing test vectors.

Symmetric protection remains classical (AEAD); only the key agreement layer is
made hybrid/PQ-ready following the recommendations from
[draft-ietf-tls-hybrid-design](https://datatracker.ietf.org/doc/html/draft-ietf-tls-hybrid-design-05).

## Performance Summary (AMD Ryzen 7, Go 1.22+)

| Category   | Algorithm          | Encrypt/Hash  | MB/s   | Allocs/op             | Notes                |
|------------|--------------------|---------------|--------|-----------------------|----------------------|
| **AEAD**   | **AES-GCM**        | 1488 MB/s     | 0      | **1.5 GB/s**          | Hardware accelerated |
| **AEAD**   | **ChaCha20-Poly**  | 178 MB/s      | 3      | Portable              |                      |
| **AEAD**   | **ASCON-128a**     | **223 MB/s**  | 3      | **Lightweight champ** |
| **AEAD**   | **Xoodyak**        | 212 MB/s      | 2      | IoT optimized         |
| **AEAD**   | **AES-SIV**        | 442 MB/s      | 13     | Nonce-misuse safe     |
| **Block**  | **AES-128**        | **1940 MB/s** | **0**  | AES-NI                |
| **Hash**   | **BLAKE2b-512**    | **742 MB/s**  | 2      | **Fastest**           |
| **Hash**   | **SHA3-256**       | 38 MB/s       | 1      | NIST standard         |
| **XOF**    | **BLAKE2b XOF**    | **189 MB/s**  | 1      | Streaming champ       |
| **KDF**    | **HKDF-SHA256**    | 27 MB/s       | 18     | Fast key derivation   |
| **KDF**    | **Argon2id**       | 0.01 MB/s     | 19 MiB | Memory-hard           |
| **MAC**    | **Poly1305**       | **3117 MB/s** | 4      | **Ultra-fast**        |
| **Stream** | **ChaCha20**       | **224 MB/s**  | **0**  | Zero allocs           |
| **Sig**    | **Ed25519 Verify** | 23 MB/s       | **0**  | Fastest signature     |
| **ECDH**   | **X25519**         | 0.82 MB/s     | 1      | Key exchange          |

**Full results**: [benchmark.md](https://github.com/AeonDave/cryptonite-go/blob/main/benchmark.md)

## Performance Highlights

- **3+ GB/s** MAC operations (Poly1305)
- **1.6+ GB/s** authenticated encryption (AES-GCM)
- **800+ MB/s** cryptographic hashing (BLAKE2b)
- **Zero allocations** on critical paths (AES, ChaCha20, Ed25519 verify)
- **Pure Go** - no CGO, cross-compile anywhere

### Unique Algorithm Support
- **ASCON-128a**: 225 MB/s (NIST Lightweight Crypto winner)
- **Xoodyak**: 216 MB/s (IoT-optimized AEAD)
- Rare algorithms: DeoxysII, GIFT-COFB, SkinnyAead

## Security and limitations

- This library has not undergone independent security audits. Do not use in production without a thorough review.
- Implementations aim to be constant-time where required (e.g., Poly1305 follows the upstream bit-sliced algorithm).
  Review and test before use in side-channel-sensitive environments.
- Algorithms require exact key/nonce sizes; invalid sizes result in errors.
- Deoxys-II produces deterministic keystream inputs and is nonce-misuse resistant, but nonces must remain unique per key
  to avoid revealing repeated plaintext keystream correlations.
