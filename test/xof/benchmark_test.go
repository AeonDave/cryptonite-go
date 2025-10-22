package xof_test

import (
	"testing"

	"github.com/AeonDave/cryptonite-go/xof"
)

func makeBytes(length int, seed byte) []byte {
	buf := make([]byte, length)
	for i := range buf {
		buf[i] = seed + byte(i)
	}
	return buf
}

func mustBlake2bXOF(length uint32) func() xof.XOF {
	return func() xof.XOF {
		inst, err := xof.Blake2b(length, nil)
		if err != nil {
			panic(err)
		}
		return inst
	}
}

func mustBlake2sXOF(length uint32) func() xof.XOF {
	return func() xof.XOF {
		inst, err := xof.Blake2s(length, nil)
		if err != nil {
			panic(err)
		}
		return inst
	}
}

func benchmarkXOF(b *testing.B, name string, newXOF func() xof.XOF) {
	input := makeBytes(4096, 0x51)
	out := make([]byte, 1024)
	b.Run(name, func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(out)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			inst := newXOF()
			if _, err := inst.Write(input); err != nil {
				b.Fatalf("write failed: %v", err)
			}
			if _, err := inst.Read(out); err != nil {
				b.Fatalf("read failed: %v", err)
			}
		}
	})
}

func BenchmarkXOF(b *testing.B) {
	specs := []struct {
		name string
		ctor func() xof.XOF
	}{
		{"SHAKE128", xof.SHAKE128},
		{"SHAKE256", xof.SHAKE256},
		{"CSHAKE128", func() xof.XOF { return xof.CSHAKE128([]byte("FN"), []byte("custom")) }},
		{"CSHAKE256", func() xof.XOF { return xof.CSHAKE256([]byte("FN"), []byte("custom")) }},
		{"Blake2bXOF", mustBlake2bXOF(64)},
		{"Blake2sXOF", mustBlake2sXOF(32)},
		{"XoodyakXOF", xof.Xoodyak},
	}
	for _, spec := range specs {
		benchmarkXOF(b, spec.name, spec.ctor)
	}
}
