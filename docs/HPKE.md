# Hybrid Public Key Encryption (HPKE)

Cryptonite-go implements RFC 9180 Hybrid Public Key Encryption (HPKE) in the `hpke` package. This document explains the
available modes, suite configuration, and integration guidance.

## Supported Modes and Suites

- **Base mode (mode 0)** is fully supported. Auth, PSK, and AuthPSK modes share the same API surface and are reachable by
  supplying the appropriate options structures.
- Predefined ciphersuite helpers mirror RFC 9180 labels:
  - `hpke.SuiteX25519ChaCha20` → KEM: DHKEM(X25519, HKDF-SHA256), KDF: HKDF-SHA256, AEAD: ChaCha20-Poly1305.
  - `hpke.SuiteX25519AESGCM` → KEM: DHKEM(X25519, HKDF-SHA256), KDF: HKDF-SHA256, AEAD: AES-256-GCM.
  - `hpke.SuiteP256ChaCha20` → KEM: DHKEM(P-256, HKDF-SHA256), KDF: HKDF-SHA256, AEAD: ChaCha20-Poly1305.

Callers can construct custom suites via `hpke.NewSuite(kemID, kdfID, aeadID)` which validates identifiers against the
registry.

## Usage Pattern

1. **Setup** – The sender creates a context with `suite.SetupBaseSender(publicKey, info)` which returns the encapsulated
   key (`enc`) and a `Context` instance. The receiver calls `suite.SetupBaseReceiver(enc, privateKey, info)`.
2. **Seal/Open** – Use `ctx.Seal(nonce, aad, pt)` and `ctx.Open(nonce, aad, ct)` to protect data. Nonces are 96-bit values
   that increment per message.
3. **Export** – Derive exporter secrets via `ctx.Export(secret, length)` for key schedule chaining.

## Deterministic Nonces

HPKE leaves nonce generation to the application. Combine the exporter interface with the HKDF-based helpers in
`secret.NewDeterministicNonce` to derive deterministic nonces that are bound to the encapsulated key and associated data.

## Integration with `pq`

The `pq` package wraps HPKE contexts to produce hybrid envelopes that mix classical and post-quantum KEMs. The flow is:

1. Call `pq.NewHybrid(classicalKEM, mlkem)` to construct the hybrid encapsulation object.
2. Use `pq.Seal` / `pq.Open` to perform HPKE-based key establishment with AEAD payload encryption.
3. The resulting format encodes HPKE metadata, AEAD identifiers, and ciphertext to ensure deterministic re-derivation of
   keys during decryption.

