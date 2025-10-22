package mac_test

import (
	"testing"

	"github.com/AeonDave/cryptonite-go/mac"
)

func makeBytes(length int, seed byte) []byte {
	buf := make([]byte, length)
	for i := range buf {
		buf[i] = seed + byte(i)
	}
	return buf
}

func BenchmarkMAC(b *testing.B) {
	msg := makeBytes(2048, 0x33)
	key := makeBytes(32, 0x11)
	polyKey := makeBytes(mac.Poly1305KeySize, 0x44)

	b.Run("HMAC-SHA256", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(msg)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = mac.Sum(key, msg)
		}
	})

	b.Run("Poly1305", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(msg)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := mac.SumPoly1305(polyKey, msg); err != nil {
				b.Fatalf("poly1305 failed: %v", err)
			}
		}
	})

	b.Run("KMAC128", func(b *testing.B) {
		customization := []byte("custom")
		b.ReportAllocs()
		b.SetBytes(int64(len(msg)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			out := mac.KMAC128(key, customization, msg, 32)
			if len(out) != 32 {
				b.Fatalf("unexpected length: %d", len(out))
			}
		}
	})

	b.Run("KMAC256", func(b *testing.B) {
		customization := []byte("custom")
		b.ReportAllocs()
		b.SetBytes(int64(len(msg)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			out := mac.KMAC256(key, customization, msg, 64)
			if len(out) != 64 {
				b.Fatalf("unexpected length: %d", len(out))
			}
		}
	})
}
