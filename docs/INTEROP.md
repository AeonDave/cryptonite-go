# Interoperability Guide

Cryptonite-go aims to interoperate with existing cryptography stacks. This guide documents wire formats, encoding rules,
and compatibility notes.

## AEAD Payloads

- **Ciphertext layout** – All AEAD encryptors return `ciphertext || tag`. For streaming AEADs, tags are always appended to
  the end of the slice.
- **Associated Data** – Provided associated data is not included in the ciphertext and must be supplied verbatim during
  decryption.
- **Nonce encoding** – Callers are responsible for storing nonces alongside ciphertext. Use big-endian encoding when
  serializing counters.

## Signature Encodings

- **Ed25519** – Signatures are 64-byte raw buffers. Public keys are 32-byte little-endian values as defined in RFC 8032.
- **ECDSA P-256** – Public keys default to uncompressed SEC1 format (`0x04 || X || Y`). Signatures follow ASN.1 DER.

## ECDH Keys

- `ecdh.NewX25519` expects 32-byte private keys and outputs 32-byte Montgomery u-coordinates. Use the standard base point
  defined in RFC 7748.
- `ecdh.NewP256` / `NewP384` accept scalar private keys and return uncompressed SEC1 public points.

## HPKE Records

- HPKE `enc` values are written exactly as produced by the underlying KEM (32 bytes for X25519, 65 for P-256).
- Ciphertexts include a 96-bit nonce supplied by the caller, AEAD ciphertext, and tag. Persist the nonce to decrypt.

## PQ Hybrid Envelopes

Hybrid envelopes emitted by `pq.Seal` are length-prefixed structures:

```
version (1 byte)
classical_ct_len (2 bytes, big-endian)
classical_ct (variable)
pq_ct_len (2 bytes, big-endian)
pq_ct (variable)
aead_id (1 byte)
nonce (len depends on AEAD)
ciphertext (variable)
tag (16 bytes typical)
```

Decoders must validate lengths before slicing the input to prevent panics. Unknown `version` values should trigger a
feature negotiation or graceful failure.

## Hashing and KDFs

- Hash functions follow the same digest outputs as Go's standard library implementations, so interoperability is
  straightforward.
- HKDF uses little-endian uint16 labels when deriving AEAD keys for the hybrid envelope format, matching the docs in
  `pq`.

