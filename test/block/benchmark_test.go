package block_test

import (
	"testing"

	"github.com/AeonDave/cryptonite-go/block"
)

func makeBytes(length int, seed byte) []byte {
	buf := make([]byte, length)
	for i := range buf {
		buf[i] = seed + byte(i)
	}
	return buf
}

func BenchmarkBlockCiphers(b *testing.B) {
	plaintext := makeBytes(16, 0x22)
	b.Run("AES-128", func(b *testing.B) {
		key := makeBytes(16, 0x11)
		cipher, err := block.NewAES128(key)
		if err != nil {
			b.Fatalf("init failed: %v", err)
		}
		dst := make([]byte, len(plaintext))
		b.ReportAllocs()
		b.SetBytes(int64(len(plaintext)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			cipher.Encrypt(dst, plaintext)
		}
	})

	b.Run("AES-256", func(b *testing.B) {
		key := makeBytes(32, 0x33)
		cipher, err := block.NewAES256(key)
		if err != nil {
			b.Fatalf("init failed: %v", err)
		}
		dst := make([]byte, len(plaintext))
		b.ReportAllocs()
		b.SetBytes(int64(len(plaintext)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			cipher.Encrypt(dst, plaintext)
		}
	})
}
