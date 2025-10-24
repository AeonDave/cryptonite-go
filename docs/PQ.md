# Post-Quantum Integration

Cryptonite-go approaches post-quantum readiness through hybrid KEM constructions that pair classical elliptic-curve
schemes with pluggable ML-KEM implementations, and through first-class ML-DSA (Dilithium) signature support.

## Hybrid Format Overview

- **Versioning** – Hybrids produced by `pq.NewHybrid` begin with a version byte so new PQ algorithms can be introduced
  without breaking decoders.
- **Length prefixes** – Classical and PQ ciphertexts are both length-prefixed, enabling variable-size payloads and simple
  framing.
- **Key schedule** – Derived shared secrets feed HKDF (SHA-256) to produce AEAD keys and nonces. The HKDF info string
  encodes the chosen AEAD to ensure domain separation.

## Classical Component

The default classical KEM is `kem.New()`, which wraps X25519 or P-256 ECDH and exposes the shared `kem.KEM` interface.
Callers can substitute their own classical implementation if they match the same interface (GenerateKey, Encapsulate,
Decapsulate).

## ML-KEM Component

To integrate ML-KEM (Kyber/ML-KEM 512/768/1024):

1. Choose a `kem.KEM` implementation for the desired parameter set. Cryptonite-go ships pure-Go variants derived from the round-3 Kyber reference:
   - `pq.NewMLKEM512()` / `pq.NewMLKEM768()` / `pq.NewMLKEM1024()` expose the NIST-standardised parameter sets.
   - KAT vectors live under `test/pq/testdata` and are exercised by `TestMLKEMKAT`.
   - Convenience hybrids `pq.NewHybridX25519MLKEM512()` (and the 768/1024 variants) wire the Kyber instances into the X25519 scaffold used elsewhere in the library.
2. Pass the KEM to `pq.NewHybrid(classical, mlkem)` or use the provided hybrid helpers directly.
3. Ensure ML-KEM public key, secret key, and ciphertext encodings follow the FIPS 203 byte layouts when exchanging material over the wire.

These helpers rely solely on `crypto/sha3` and require no third-party dependencies.

## Envelope Helpers

`pq.Seal` and `pq.Open` provide a turnkey envelope construction:

- The sender encapsulates via both classical and PQ components, concatenates the ciphertexts, and derives AEAD keys.
- The receiver decapsulates each component independently and recombines secrets. If the PQ side fails, implementations
  should treat the message as invalid even if the classical component succeeds.

## Key Management Tips

- **Rotate keys** regularly: publish new hybrid public keys once PQ implementations are updated.
- **Secure storage**: Store ML-KEM secret keys with strong access controls; they are typically larger than classical keys.
- **Fallbacks**: If the PQ component is unavailable, degrade gracefully by using the classical KEM only, but log the event
  so operators are aware of reduced security.

## ML-DSA Signatures

- `sig.NewMLDSA44/65/87()` expose the NIST-standardised Dilithium (ML-DSA) variants with randomized signing by default.
- Deterministic constructors (`sig.NewDeterministicMLDSAxx`) and seed-based key generation helpers enable KAT reproduction
  and strict interoperability testing.
- All implementations are pure Go with no third-party dependencies and share the same `sig.Signature` interface as
  classical schemes, making it straightforward to slot ML-DSA into existing signing pipelines.
- Official NIST KAT vectors are vendored under `test/sig/testdata` and executed by `TestMLDSAKAT`.

