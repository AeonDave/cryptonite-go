# Nonce and Counter Management

Cryptonite-go offers both deterministic SIV constructions and classic nonce-based AEADs. Correctly managing nonces and
counters is critical for security; this guide summarizes best practices across the library.

## General Guidelines

- **Uniqueness is mandatory**: For nonce-based AEADs (AES-GCM, ChaCha20-Poly1305, ASCON, etc.) never reuse a nonce with
the same key. Reuse undermines confidentiality and integrity.
- **Leverage `secret.Nonce` helpers**: The `secret` package exposes reference types for random nonces and monotonic
  counters. Use them to reduce mistakes and enable zeroization via `Destroy()`.
- **Avoid truncating randomness**: When generating nonces, use the exact byte length required by the algorithm. Trimming
  randomness to a smaller size introduces collisions.
- **Secure storage**: Persist counters alongside encrypted data so you can resume sequences safely after restarts.
- **Parallelization**: When encrypting in parallel, partition the nonce space (e.g., prefix worker ID bits) or derive
  subkeys with HKDF so each worker owns an independent key/nonce pair.

## AEAD-specific Recommendations

### ChaCha20-Poly1305 and AES-GCM

- Use 96-bit nonces (`12 bytes`). Compose a deterministic nonce by concatenating a 32-bit big-endian counter with a
  64-bit random prefix, or derive nonces via HKDF when using key encapsulation flows (see `pq.Seal`).
- For AES-GCM counters, ensure the low 32 bits increment monotonically and never wrap. Callers should detect counter
  exhaustion and rotate keys before the 2³² limit.

### XChaCha20-Poly1305

- Supply a full 192-bit (`24-byte`) nonce. The constructor internally runs HChaCha20 to derive a subkey and 96-bit nonce
  for ChaCha20, so uniqueness of the 192-bit input is sufficient.

### AES-GCM-SIV and AES-SIV

- These constructions are nonce-misuse resistant but **not** misuse-proof. Repeating nonces will not leak plaintext, yet
  it still enables replay. Generate high-entropy nonces and include strict associated data for replay detection.
- When using `aead.MultiAssociatedData`, keep the ordering of pieces consistent between encryption and decryption.

### Lightweight AEADs (ASCON, SKINNY, GIFT-COFB, Xoodyak)

- Follow the same 128-bit nonce uniqueness rules. For microcontrollers, monotonic counters stored in flash are
  acceptable as long as updates are atomic (use double-buffering or sequence numbers).

## Counter Utilities

The `secret` package provides reusable counter implementations:

- `secret.NewMonotonicCounter(size)` – returns a fixed-width big-endian counter. Use `Increment()` to advance and
  `Bytes()` to obtain the current value.
- `secret.NewDeterministicNonce(key, salt, info)` – HKDF-based deterministic nonce derivation that binds context strings
  to the output.
- `secret.Zeroize()` – helper to clear sensitive buffers once a nonce or counter leaves scope.

## Zeroization Checklist

1. Destroy nonce/counter structures once completed (`defer nonce.Destroy()`).
2. Wipe temporary copies of nonces stored in slices or structs.
3. Guard against double-destruction by setting references to `nil` after zeroization.

