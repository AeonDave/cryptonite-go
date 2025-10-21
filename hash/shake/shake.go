package shake

import "cryptonite-go/internal/keccak"

type XOF struct {
	sponge keccak.Sponge
}

func newXOF(rate int, ds byte) *XOF {
	var x XOF
	x.sponge.Init(rate, ds)
	return &x
}

func (x *XOF) Write(p []byte) (int, error) {
	x.sponge.Absorb(p)
	return len(p), nil
}

func (x *XOF) Read(out []byte) (int, error) {
	x.sponge.Squeeze(out)
	return len(out), nil
}

func (x *XOF) Reset() {
	x.sponge.Reset()
}

func NewSHAKE128() *XOF { return newXOF(168, 0x1f) }
func NewSHAKE256() *XOF { return newXOF(136, 0x1f) }
