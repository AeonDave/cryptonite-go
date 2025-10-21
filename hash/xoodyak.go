package hash

import (
	stdhash "hash"

	xo "cryptonite-go/internal/xoodyak"
)

const DigestSize = 32

// Hash implements the Xoodyak hash function (32-byte digest) using the Cyclist hash mode.
type Hash struct {
	inst xo.Instance
}

// NewXoodyak returns a hash.Hash computing the 32-byte Xoodyak digest.
func NewXoodyak() stdhash.Hash {
	h := &Hash{}
	h.Reset()
	return h
}

// NewXoodyakHasher returns a stateless helper implementing hash.Hasher for Xoodyak.
func NewXoodyakHasher() Hasher { return xoodyakHasher{} }

func (h *Hash) Reset() {
	_ = h.inst.Initialize(nil, nil, nil)
}

func (h *Hash) Write(p []byte) (int, error) {
	h.inst.Absorb(p)
	return len(p), nil
}

func (h *Hash) Sum(b []byte) []byte {
	tmp := h.inst
	out := make([]byte, DigestSize)
	tmp.SqueezeAny(out, 0x00)
	return append(b, out...)
}

// Hash computes the digest of msg without altering the streaming state.
func (h *Hash) Hash(msg []byte) []byte {
	d := SumXoodyak(msg)
	out := make([]byte, DigestSize)
	copy(out, d[:])
	return out
}

func (h *Hash) Size() int      { return DigestSize }
func (h *Hash) BlockSize() int { return xo.HashRate }

// SumXoodyak returns the Xoodyak hash of msg.
func SumXoodyak(msg []byte) [DigestSize]byte {
	var inst xo.Instance
	if err := inst.Initialize(nil, nil, nil); err != nil {
		panic("xoodyak: unexpected initialize failure")
	}
	inst.Absorb(msg)
	var out [DigestSize]byte
	inst.SqueezeAny(out[:], 0x00)
	return out
}

type xoodyakHasher struct{}

func (xoodyakHasher) Hash(msg []byte) []byte {
	d := SumXoodyak(msg)
	out := make([]byte, DigestSize)
	copy(out, d[:])
	return out
}

func (xoodyakHasher) Size() int { return DigestSize }

type xoodyakXOF struct {
	inst    xo.Instance
	started bool
}

func newXoodyakXOF() *xoodyakXOF {
	var x xoodyakXOF
	x.Reset()
	return &x
}

func (x *xoodyakXOF) Reset() {
	_ = x.inst.Initialize(nil, nil, nil)
	x.started = false
}

func (x *xoodyakXOF) Write(p []byte) (int, error) {
	x.inst.Absorb(p)
	return len(p), nil
}

func (x *xoodyakXOF) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if x.started {
		x.inst.Advance()
	} else {
		x.started = true
	}
	x.inst.SqueezeAny(p, 0x00)
	return len(p), nil
}

// NewXoodyakXOF creates a new Xoodyak extendable-output instance.
func NewXoodyakXOF() XOF { return wrapXOF(newXoodyakXOF()) }
