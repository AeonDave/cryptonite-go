package xof

import "cryptonite-go/internal/xoodyak"

type xoodyakXOF struct {
	inst    xoodyak.Instance
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

// Xoodyak returns a new Xoodyak extendable-output instance.
func Xoodyak() XOF { return newXoodyakXOF() }
