package xof

import "cryptonite-go/internal/keccak"

type shakeXOF struct {
	sponge keccak.Sponge
	rate   int
	ds     byte
}

func newShakeXOF(rate int, ds byte) *shakeXOF {
	x := &shakeXOF{rate: rate, ds: ds}
	x.sponge.Init(rate, ds)
	return x
}

func (x *shakeXOF) Write(p []byte) (int, error) {
	x.sponge.Absorb(p)
	return len(p), nil
}

func (x *shakeXOF) Read(out []byte) (int, error) {
	x.sponge.Squeeze(out)
	return len(out), nil
}

func (x *shakeXOF) Reset() {
	x.sponge.Init(x.rate, x.ds)
}

func newSHAKEXOF(rate int, ds byte) XOF {
	return newShakeXOF(rate, ds)
}

func SHAKE128() XOF { return newSHAKEXOF(168, 0x1f) }
func SHAKE256() XOF { return newSHAKEXOF(136, 0x1f) }
