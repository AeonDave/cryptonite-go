# Algorithm Reference

This document captures the complete algorithm matrix for Cryptonite-go. It mirrors the tables previously hosted in
`README.md` and includes key sizes, nonce formats, tags, and primary specification references.

## AEAD

| Algorithm          | Constructor(s)                                 | Key       | Nonce               | Tag | Notes                                                                             | RFC / Spec                                                                                      |
|--------------------|------------------------------------------------|-----------|---------------------|-----|-----------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| ASCON-128a         | `aead.NewAscon128()`                           | 16B       | 16B                 | 16B | NIST LwC winner                                                                   | [FIPS 208](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.208.pdf)                             |
| ASCON-80pq         | `aead.NewAscon80pq()`                          | 20B       | 16B                 | 16B | PQ-hardened variant                                                               | [FIPS 208](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.208.pdf)                             |
| GIFT-COFB          | `aead.NewGiftCofb()`                           | 16B       | 16B                 | 16B | Ultra-lightweight finalist                                                        | [IACR 2018/803](https://eprint.iacr.org/2018/803.pdf)                                            |
| SKINNY-AEAD-M1     | `aead.NewSkinnyAead()`                         | 16B       | 16B                 | 16B | Tweakable block-cipher AEAD (128-bit tag)                                         | [NIST LwC Round 1 submission](https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/round-1/submissions/SKINNY.pdf) |
| Xoodyak-Encrypt    | `aead.NewXoodyak()`                            | 16B       | 16B                 | 16B | Cyclist mode                                                                      | [Xoodyak specification](https://keccak.team/files/Xoodyak-specification.pdf)                     |
| ChaCha20-Poly1305  | `aead.NewChaCha20Poly1305()`                   | 32B       | 12B                 | 16B | RFC 8439 layout                                                                   | [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439.html)                                          |
| XChaCha20-Poly1305 | `aead.NewXChaCha20Poly1305()`                  | 32B       | 24B                 | 16B | Derives nonce via HChaCha20                                                       | [draft-irtf-cfrg-xchacha-03](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03)   |
| AES-GCM            | `aead.NewAESGCM()`                             | 16/24/32B | 12B                 | 16B | AES-NI optional                                                                   | [NIST SP 800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf) |
| AES-GCM-SIV        | `aead.NewAesGcmSiv()`                          | 16/32B    | 12B                 | 16B | Nonce misuse resistant                                                            | [RFC 8452](https://www.rfc-editor.org/rfc/rfc8452.html)                                          |
| AES-SIV (128/256)  | `aead.NewAES128SIV()`<br>`aead.NewAES256SIV()` | 32B / 64B | Deterministic (AAD) | 16B | Deterministic SIV construction; optional multi-AD support via `aead.MultiAssociatedData` | [RFC 5297](https://www.rfc-editor.org/rfc/rfc5297.html)                                          |
| Deoxys-II-256-128  | `aead.NewDeoxysII128()`                        | 32B       | 15B                 | 16B | NIST LwC finalist                                                                  | [NIST LWC finalist spec](https://csrc.nist.gov/csrc/media/Projects/lightweight-cryptography/documents/finalists/deoxys-spec-final.pdf) |

## Hashing

Every hashing entry point lives under the `hash` package so callers can rely on the uniform `hash.Hasher` interface or
the Go `hash.Hash` type without importing algorithm-specific subpackages.

| Algorithm    | Streaming constructor                            | Single-shot helper(s)                           | Notes                                           | RFC / Spec                                                                   |
|--------------|--------------------------------------------------|-------------------------------------------------|-------------------------------------------------|------------------------------------------------------------------------------|
| SHA3-224     | `hash.NewSHA3224()`                              | `hash.NewSHA3224Hasher()` / `hash.Sum224`       | 224-bit (28B) digest                            | [FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)         |
| SHA3-256     | `hash.NewSHA3256()`                              | `hash.NewSHA3256Hasher()` / `hash.Sum256`       | 256-bit (32B) digest                            | [FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)         |
| SHA3-384     | `hash.NewSHA3384()`                              | `hash.NewSHA3384Hasher()` / `hash.Sum384`       | 384-bit (48B) digest                            | [FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)         |
| SHA3-512     | `hash.NewSHA3512()`                              | `hash.NewSHA3512Hasher()` / `hash.Sum512`       | 512-bit (64B) digest                            | [FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)         |
| BLAKE2b      | `hash.NewBlake2b()` / `hash.NewBlake2bBuilder()` | `hash.NewBlake2bHasher()`                       | Configurable 1–64B digest, optional keyed MAC mode | [RFC 7693](https://www.rfc-editor.org/rfc/rfc7693.html)                      |
| BLAKE2s      | `hash.NewBlake2s()` / `hash.NewBlake2sBuilder()` | `hash.NewBlake2sHasher()`                       | Configurable 1–32B digest, optional keyed MAC mode | [RFC 7693](https://www.rfc-editor.org/rfc/rfc7693.html)                      |
| Xoodyak Hash | `hash.NewXoodyak()`                              | `hash.NewXoodyakHasher()` / `hash.SumXoodyak()` | 32B Cyclist hash                                | [Xoodyak specification](https://keccak.team/files/Xoodyak-specification.pdf) |

### SP 800-185 constructions

| Algorithm             | Helper(s)                                                                              | Notes                                             | RFC / Spec                                                                                   |
|-----------------------|----------------------------------------------------------------------------------------|---------------------------------------------------|----------------------------------------------------------------------------------------------|
| TupleHash128 / 256    | `hash.TupleHash128(tuple, outLen, customization)` / `hash.TupleHash256`                | Tuple of byte-strings, optional customization     | [NIST SP 800-185](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf) |
| ParallelHash128 / 256 | `hash.ParallelHash128(msg, blockSize, outLen, customization)` / `hash.ParallelHash256` | Parallel-friendly hashing for large messages      | [NIST SP 800-185](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf) |

## XOF (Extendable-output function)

Constructors live under the dedicated `xof` package and return the shared `xof.XOF` interface so extendable-output
primitives can be swapped transparently.

| Algorithm   | Constructor      | Notes                                      | RFC / Spec                                      |
|-------------|------------------|--------------------------------------------|-------------------------------------------------|
| SHAKE128    | `xof.NewShake128()` | 256-bit security level; arbitrary output length | [FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) |
| SHAKE256    | `xof.NewShake256()` | 512-bit security level; arbitrary output length | [FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf) |
| BLAKE2XOF   | `xof.NewBlake2XOF()` | BLAKE2b-based extendable-output mode         | [RFC 7693](https://www.rfc-editor.org/rfc/rfc7693.html)              |
| Xoodyak XOF | `xof.NewXoodyakXOF()` | Cyclist XOF variant                           | [Xoodyak specification](https://keccak.team/files/Xoodyak-specification.pdf) |

## Key Derivation (KDF)

| Algorithm | Constructor / Helper(s)                                      | Notes                                                        | RFC / Spec                                                                 |
|-----------|--------------------------------------------------------------|--------------------------------------------------------------|-----------------------------------------------------------------------------|
| HKDF      | `kdf.NewHKDF(sha256)` / `kdf.NewHKDF(blake2b)`               | Modern extract-and-expand with pluggable hash                | [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html)                     |
| Argon2id  | `kdf.Argon2id(params)`                                      | Memory-hard password hashing                                 | [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html)                     |
| scrypt    | `kdf.Scrypt(params)`                                        | Memory-hard password hashing                                 | [RFC 7914](https://www.rfc-editor.org/rfc/rfc7914.html)                     |
| PBKDF2    | `kdf.PBKDF2(password, salt, iter, keyLen, hashFunc)`        | Password-based KDF with SHA-1 / SHA-256                      | [PKCS #5 v2.1](https://www.rfc-editor.org/rfc/rfc8018.html)                 |

## MAC

| Algorithm   | Helper(s)                                                           | Key        | Tag | Notes                                          | RFC / Spec                                       |
|-------------|---------------------------------------------------------------------|------------|-----|------------------------------------------------|--------------------------------------------------|
| HMAC-SHA256 | `mac.Sum(key, data)`<br>`mac.Verify(key, data, tag)`                | Any length | 32B | Single-shot helpers over SHA-256               | [RFC 2104](https://www.rfc-editor.org/rfc/rfc2104.html) |
| Poly1305    | `mac.NewPoly1305(key)`<br>`mac.SumPoly1305()`<br>`mac.VerifyPoly1305()` | 32B (one-time) | 16B | One-time key per message (RFC 7539)            | [RFC 7539](https://www.rfc-editor.org/rfc/rfc7539.html) |

## Stream ciphers

`stream.NewChaCha20` and `stream.NewXChaCha20` expose the shared `stream.Stream` interface (with `Reset`, `KeyStream`,
and `XORKeyStream`) so applications can swap keystream generators without touching call sites.

| Algorithm | Constructor             | Key       | Nonce | Notes                                          | RFC / Spec                                                                             |
|-----------|-------------------------|-----------|-------|------------------------------------------------|----------------------------------------------------------------------------------------|
| AES-CTR   | `stream.NewAESCTR()`    | 16/24/32B | 12B   | 96-bit nonce with 32-bit counter (NIST layout) | [NIST SP 800-38A](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf) |
| ChaCha20  | `stream.NewChaCha20()`  | 32B       | 12B   | IETF variant with configurable counter         | [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439.html)                                 |
| XChaCha20 | `stream.NewXChaCha20()` | 32B       | 24B   | HChaCha20-derived subkeys and raw keystream    | [draft-irtf-cfrg-xchacha-03](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03)   |

## Block ciphers

Block primitives are instantiated through `block.NewAES128` / `block.NewAES256`, both returning the shared
`block.Cipher` interface.

| Algorithm | Constructor         | Key | Block | Notes                        | RFC / Spec                                        |
|-----------|---------------------|-----|-------|------------------------------|--------------------------------------------------|
| AES-128   | `block.NewAES128()` | 16B | 16B   | Thin wrapper over stdlib AES | [FIPS 197](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf) |
| AES-256   | `block.NewAES256()` | 32B | 16B   | Thin wrapper over stdlib AES | [FIPS 197](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf) |

## Signatures

| Algorithm   | Constructor(s)       | Public             | Private    | Signature            | Notes                                                | RFC / Spec                                                               |
|-------------|----------------------|--------------------|------------|----------------------|------------------------------------------------------|--------------------------------------------------------------------------|
| Ed25519     | `sig.NewEd25519()`   | 32B                | 64B        | 64B                  | Deterministic; `sig.FromSeed(32B)` supported         | [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html)                  |
| ECDSA P-256 | `sig.NewECDSAP256()` | 65B (uncompressed) | 32B scalar | ASN.1 DER (variable) | Helpers: `sig.GenerateKeyECDSAP256`, `sig.SignECDSAP256`, `sig.VerifyECDSAP256` | [FIPS 186-5](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf) |

Ed25519 builds directly on Go's standard library implementation (`crypto/ed25519`) and re-exports the canonical buffer
sizes via `sig.PublicKeySize`, `sig.PrivateKeySize`, `sig.SeedSize`, and `sig.SignatureSize`. The package also provides
an alias for `ed25519.Options` together with helpers that cover all RFC 8032 variants:

- `sig.SignWithOptions(priv, msg, opts)` – supports standard, context-bound, and pre-hash signing through the stdlib's
  `ed25519.PrivateKey.Sign` API.
- `sig.VerifyWithOptions(pub, msg, sig, opts)` – validates inputs, defaults to RFC 8032 parameters, and dispatches to
  `crypto/ed25519.VerifyWithOptions`.

These additions allow advanced Ed25519 flows without reimplementing the algorithm or importing `crypto/ed25519` at call
sites.

## Key Exchange (ECDH)

| Algorithm | Constructor      | Public             | Private    | Shared | Notes                                   | RFC / Spec                                                               |
|-----------|------------------|--------------------|------------|--------|-----------------------------------------|--------------------------------------------------------------------------|
| X25519    | `ecdh.NewX25519()` | 32B                | 32B        | 32B    | RFC 7748 (crypto/ecdh)                  | [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748.html)                  |
| P-256     | `ecdh.NewP256()` | 65B (uncompressed) | 32B scalar | 32B    | Uncompressed public: 0x04 || X || Y     | [FIPS 186-5](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf) |
| P-384     | `ecdh.NewP384()` | 97B (uncompressed) | 48B scalar | 48B    | Uncompressed public: 0x04 || X || Y     | [FIPS 186-5](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf) |

## Post-quantum key encapsulation

The `kem` package defines a shared `kem.KEM` interface together with a deployable hybrid construction:

- `kem.New()` - classical KEM adapter built on top of the existing `ecdh` helpers (deployable today, pure Go, stdlib only).
  The adapter lives in the `kem` package to highlight that it provides classical security and can be reused by non-PQ
  code paths.
- `pq.NewHybridX25519()` - versioned hybrid format that composes the X25519 exchange with an optional ML-KEM component.
  Callers can inject a vetted ML-KEM implementation via `pq.NewHybrid(classical, mlkem)` without changing encoded
  formats or downstream APIs.

Key material and ciphertexts produced by the hybrid construction are encoded as
`version || len(classical) || classical || len(pq) || pq`, providing forwards compatibility when the PQ component is
introduced.

To encrypt payloads, the package also includes the convenience `pq.Seal` and `pq.Open` helpers which perform the
standard `KEM → HKDF → AEAD` flow. The envelope format embeds the encapsulated key (length-prefixed), a key-schedule
identifier, and the AEAD ciphertext so that the receiver can deterministically reproduce the derived key/nonce pair. The
key schedule currently covers modern AEADs such as ChaCha20-Poly1305, AES-256-GCM, AES-GCM-SIV, XChaCha20-Poly1305,
ASCON-128a, Deoxys-II-256-128, and the AES-SIV family.

