package pq_test

import (
	"testing"

	"github.com/AeonDave/cryptonite-go/aead"
	"github.com/AeonDave/cryptonite-go/pq"
)

func makeBytes(length int, seed byte) []byte {
	buf := make([]byte, length)
	for i := range buf {
		buf[i] = seed + byte(i)
	}
	return buf
}

func BenchmarkHybridKEM(b *testing.B) {
	hybrid := pq.NewHybridX25519()
	pub, priv, err := hybrid.GenerateKey()
	if err != nil {
		b.Fatalf("keygen failed: %v", err)
	}
	b.Run("Encapsulate", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, _, err := hybrid.Encapsulate(pub); err != nil {
				b.Fatalf("encapsulate failed: %v", err)
			}
		}
	})
	ct, shared, err := hybrid.Encapsulate(pub)
	if err != nil {
		b.Fatalf("encapsulate failed: %v", err)
	}
	b.Run("Decapsulate", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(shared)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := hybrid.Decapsulate(priv, ct); err != nil {
				b.Fatalf("decapsulate failed: %v", err)
			}
		}
	})
}

func BenchmarkEnvelope(b *testing.B) {
	hybrid := pq.NewHybridX25519()
	pub, priv, err := hybrid.GenerateKey()
	if err != nil {
		b.Fatalf("keygen failed: %v", err)
	}
	cipher := aead.NewChaCha20Poly1305()
	ad := []byte("aad")
	msg := makeBytes(1024, 0x31)

	b.Run("Seal", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(msg)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := pq.Seal(hybrid, cipher, pub, ad, msg); err != nil {
				b.Fatalf("seal failed: %v", err)
			}
		}
	})

	blob, err := pq.Seal(hybrid, cipher, pub, ad, msg)
	if err != nil {
		b.Fatalf("seal failed: %v", err)
	}

	b.Run("Open", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(msg)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := pq.Open(hybrid, cipher, priv, ad, blob); err != nil {
				b.Fatalf("open failed: %v", err)
			}
		}
	})
}
