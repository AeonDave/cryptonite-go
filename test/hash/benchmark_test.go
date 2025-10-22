package xoodyak_test

import (
	"testing"

	cryptohash "github.com/AeonDave/cryptonite-go/hash"
)

func makeBytes(length int, seed byte) []byte {
	buf := make([]byte, length)
	for i := range buf {
		buf[i] = seed + byte(i)
	}
	return buf
}

func mustBlake2bHasher(size int) func() cryptohash.Hasher {
	return func() cryptohash.Hasher {
		h, err := cryptohash.NewBlake2bHasher(size, nil)
		if err != nil {
			panic(err)
		}
		return h
	}
}

func mustBlake2sHasher(size int) func() cryptohash.Hasher {
	return func() cryptohash.Hasher {
		h, err := cryptohash.NewBlake2sHasher(size, nil)
		if err != nil {
			panic(err)
		}
		return h
	}
}

func BenchmarkHashers(b *testing.B) {
	msg := makeBytes(4096, 0x21)
	specs := []struct {
		name string
		ctor func() cryptohash.Hasher
	}{
		{"SHA3-224", func() cryptohash.Hasher { return cryptohash.NewSHA3224Hasher() }},
		{"SHA3-256", func() cryptohash.Hasher { return cryptohash.NewSHA3256Hasher() }},
		{"SHA3-384", func() cryptohash.Hasher { return cryptohash.NewSHA3384Hasher() }},
		{"SHA3-512", func() cryptohash.Hasher { return cryptohash.NewSHA3512Hasher() }},
		{"BLAKE2b-512", mustBlake2bHasher(64)},
		{"BLAKE2s-256", mustBlake2sHasher(32)},
		{"XoodyakHash", func() cryptohash.Hasher { return cryptohash.NewXoodyakHasher() }},
	}
	for _, spec := range specs {
		spec := spec
		b.Run(spec.name, func(b *testing.B) {
			hasher := spec.ctor()
			b.ReportAllocs()
			b.SetBytes(int64(len(msg)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if out := hasher.Hash(msg); len(out) != hasher.Size() {
					b.Fatalf("unexpected digest length: %d", len(out))
				}
			}
		})
	}
}

func BenchmarkSP800185(b *testing.B) {
	tuple := [][]byte{makeBytes(128, 0x10), makeBytes(64, 0x20), makeBytes(32, 0x30)}
	payload := makeBytes(4096, 0x40)
	b.Run("TupleHash128", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(tuple[0]) + len(tuple[1]) + len(tuple[2])))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if out, err := cryptohash.TupleHash128(tuple, 32, nil); err != nil || len(out) != 32 {
				b.Fatalf("unexpected result: %v (len=%d)", err, len(out))
			}
		}
	})
	b.Run("TupleHash256", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(tuple[0]) + len(tuple[1]) + len(tuple[2])))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if out, err := cryptohash.TupleHash256(tuple, 64, nil); err != nil || len(out) != 64 {
				b.Fatalf("unexpected result: %v (len=%d)", err, len(out))
			}
		}
	})
	b.Run("ParallelHash128", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(payload)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if out, err := cryptohash.ParallelHash128(payload, 256, 32, nil); err != nil || len(out) != 32 {
				b.Fatalf("unexpected result: %v (len=%d)", err, len(out))
			}
		}
	})
	b.Run("ParallelHash256", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(payload)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if out, err := cryptohash.ParallelHash256(payload, 256, 64, nil); err != nil || len(out) != 64 {
				b.Fatalf("unexpected result: %v (len=%d)", err, len(out))
			}
		}
	})
}
