package xoodyak

import (
	"hash"

	xo "cryptonite-go/internal/xoodyak"
)

const DigestSize = 32

// Hash implements the Xoodyak hash function (32-byte digest) using the Cyclist hash mode.
type Hash struct {
	inst xo.Instance
}

// New returns a hash.Hash computing the 32-byte Xoodyak digest.
func New() hash.Hash {
	h := &Hash{}
	h.Reset()
	return h
}

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

func (h *Hash) Size() int      { return DigestSize }
func (h *Hash) BlockSize() int { return xo.HashRate }

// XOF implements the Xoodyak extendable-output function.
type XOF struct {
	inst    xo.Instance
	started bool
}

// NewXOF creates a new Xoodyak XOF instance.
func NewXOF() *XOF {
	var x XOF
	_ = x.inst.Initialize(nil, nil, nil)
	return &x
}

// Reset clears the XOF state.
func (x *XOF) Reset() {
	_ = x.inst.Initialize(nil, nil, nil)
	x.started = false
}

// Write absorbs data into the XOF.
func (x *XOF) Write(p []byte) (int, error) {
	x.inst.Absorb(p)
	return len(p), nil
}

// Read squeezes output bytes from the XOF.
func (x *XOF) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if x.started {
		x.inst.Advance()
		x.inst.SqueezeAny(p, 0x00)
	} else {
		x.inst.SqueezeAny(p, 0x00)
		x.started = true
	}
	return len(p), nil
}
