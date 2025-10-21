package hash

// Hasher defines the minimal single-shot hashing API exposed by the library.
//
// It mirrors the simple AEAD interface in the aead package by offering a
// uniform helper for computing fixed-length digests without having to use the
// streaming hash.Hash interface from the standard library. Implementations are
// expected to be stateless and may be backed by any of the concrete hash
// primitives exposed under hash/.
//
// Hash computes the digest of msg and returns the resulting bytes.
// Size reports the digest length in bytes.
type Hasher interface {
	Hash(msg []byte) []byte
	Size() int
}
