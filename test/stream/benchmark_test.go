package stream_test

import (
	"testing"

	"github.com/AeonDave/cryptonite-go/stream"
)

func makeBytes(length int, seed byte) []byte {
	buf := make([]byte, length)
	for i := range buf {
		buf[i] = seed + byte(i)
	}
	return buf
}

func BenchmarkStreamCiphers(b *testing.B) {
	key := makeBytes(32, 0x01)
	nonce12 := makeBytes(12, 0x02)
	nonce24 := makeBytes(24, 0x03)
	plaintext := makeBytes(4096, 0x55)

	b.Run("ChaCha20", func(b *testing.B) {
		cipher, err := stream.NewChaCha20(key, nonce12, 1)
		if err != nil {
			b.Fatalf("init failed: %v", err)
		}
		src := make([]byte, len(plaintext))
		dst := make([]byte, len(plaintext))
		b.ReportAllocs()
		b.SetBytes(int64(len(plaintext)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			cipher.Reset(1)
			copy(src, plaintext)
			cipher.XORKeyStream(dst, src)
		}
	})

	b.Run("XChaCha20", func(b *testing.B) {
		cipher, err := stream.NewXChaCha20(key, nonce24, 1)
		if err != nil {
			b.Fatalf("init failed: %v", err)
		}
		src := make([]byte, len(plaintext))
		dst := make([]byte, len(plaintext))
		b.ReportAllocs()
		b.SetBytes(int64(len(plaintext)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			cipher.Reset(1)
			copy(src, plaintext)
			cipher.XORKeyStream(dst, src)
		}
	})
}
