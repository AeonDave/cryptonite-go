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

type xofImpl interface {
	Reset()
	Write([]byte) (int, error)
	Read([]byte) (int, error)
}

// XOF is a generic extendable-output function wrapper that delegates to an
// underlying implementation (Xoodyak, SHAKE, ...). The concrete behaviour is
// selected by the constructor used to obtain the instance.
type XOF struct {
	impl xofImpl
}

func wrapXOF(impl xofImpl) *XOF {
	if impl == nil {
		panic("hash: nil XOF implementation")
	}
	return &XOF{impl: impl}
}

// Reset reinitialises the XOF to its initial state.
func (x *XOF) Reset() {
	x.impl.Reset()
}

// Write absorbs data into the XOF.
func (x *XOF) Write(p []byte) (int, error) {
	return x.impl.Write(p)
}

// Read squeezes output bytes from the XOF.
func (x *XOF) Read(out []byte) (int, error) {
	return x.impl.Read(out)
}
