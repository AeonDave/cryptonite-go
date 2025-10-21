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

// XOF represents an extendable-output function backed by one of the concrete
// primitives exposed by the hash package (SHAKE, BLAKE2X, Xoodyak, ...).
type XOF interface {
	Reset()
	Write([]byte) (int, error)
	Read([]byte) (int, error)
}

type xofWrapper struct {
	impl xofImpl
}

func wrapXOF(impl xofImpl) XOF {
	if impl == nil {
		panic("hash: nil XOF implementation")
	}
	return &xofWrapper{impl: impl}
}

func (x *xofWrapper) Reset()                       { x.impl.Reset() }
func (x *xofWrapper) Write(p []byte) (int, error)  { return x.impl.Write(p) }
func (x *xofWrapper) Read(out []byte) (int, error) { return x.impl.Read(out) }
