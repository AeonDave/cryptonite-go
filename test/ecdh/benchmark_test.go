package ecdh_test

import (
	"testing"

	"github.com/AeonDave/cryptonite-go/ecdh"
)

func BenchmarkECDH(b *testing.B) {
	specs := []struct {
		name string
		ke   ecdh.KeyExchange
	}{
		{"X25519", ecdh.NewX25519()},
		{"P-256", ecdh.NewP256()},
		{"P-384", ecdh.NewP384()},
	}
	for _, spec := range specs {
		spec := spec
		b.Run(spec.name, func(b *testing.B) {
			privA, err := spec.ke.GenerateKey()
			if err != nil {
				b.Fatalf("keygen failed: %v", err)
			}
			privB, err := spec.ke.GenerateKey()
			if err != nil {
				b.Fatalf("peer keygen failed: %v", err)
			}
			peer := privB.PublicKey()
			b.ReportAllocs()
			secret, err := spec.ke.SharedSecret(privA, peer)
			if err != nil {
				b.Fatalf("shared secret failed: %v", err)
			}
			b.SetBytes(int64(len(secret)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := spec.ke.SharedSecret(privA, peer); err != nil {
					b.Fatalf("shared secret failed: %v", err)
				}
			}
		})
	}
}
