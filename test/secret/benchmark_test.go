package secret_test

import (
	"testing"

	"github.com/AeonDave/cryptonite-go/secret"
)

func makeBytes(length int, seed byte) []byte {
	buf := make([]byte, length)
	for i := range buf {
		buf[i] = seed + byte(i)
	}
	return buf
}

func BenchmarkSecret(b *testing.B) {
	key := secret.SymmetricKeyFrom(makeBytes(32, 0x51))
	b.Run("SymmetricKey/Use", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := key.Use(func(buf []byte) error { return nil }); err != nil {
				b.Fatalf("use failed: %v", err)
			}
		}
	})

	b.Run("SymmetricKey/Bytes", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if out, err := key.Bytes(); err != nil || len(out) != key.Len() {
				b.Fatalf("bytes failed: %v len=%d", err, len(out))
			}
		}
	})

	counter96, err := secret.NewCounter96(makeBytes(12, 0x11))
	if err != nil {
		b.Fatalf("counter96 init failed: %v", err)
	}
	b.Run("Counter96/Next", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := counter96.Next(); err != nil {
				b.Fatalf("next failed: %v", err)
			}
		}
	})

	counter192, err := secret.NewCounter192(makeBytes(24, 0x22))
	if err != nil {
		b.Fatalf("counter192 init failed: %v", err)
	}
	b.Run("Counter192/Next", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := counter192.Next(); err != nil {
				b.Fatalf("next failed: %v", err)
			}
		}
	})
}
