package sig_test

import (
	"testing"

	"github.com/AeonDave/cryptonite-go/sig"
)

func makeBytes(length int, seed byte) []byte {
	buf := make([]byte, length)
	for i := range buf {
		buf[i] = seed + byte(i)
	}
	return buf
}

func BenchmarkSignatures(b *testing.B) {
	msg := makeBytes(1024, 0x71)

	ed := sig.NewEd25519()
	edPub, edPriv, err := ed.GenerateKey()
	if err != nil {
		b.Fatalf("ed25519 keygen failed: %v", err)
	}
	edSig, err := ed.Sign(edPriv, msg)
	if err != nil {
		b.Fatalf("ed25519 sign failed: %v", err)
	}

	b.Run("Ed25519/Sign", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(msg)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := ed.Sign(edPriv, msg); err != nil {
				b.Fatalf("sign failed: %v", err)
			}
		}
	})

	b.Run("Ed25519/Verify", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(msg)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if !ed.Verify(edPub, msg, edSig) {
				b.Fatalf("verify failed")
			}
		}
	})

	p256 := sig.NewECDSAP256()
	pPub, pPriv, err := p256.GenerateKey()
	if err != nil {
		b.Fatalf("ecdsa keygen failed: %v", err)
	}
	pSig, err := p256.Sign(pPriv, msg)
	if err != nil {
		b.Fatalf("ecdsa sign failed: %v", err)
	}

	b.Run("ECDSAP256/Sign", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(msg)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := p256.Sign(pPriv, msg); err != nil {
				b.Fatalf("sign failed: %v", err)
			}
		}
	})

	b.Run("ECDSAP256/Verify", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(msg)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if !p256.Verify(pPub, msg, pSig) {
				b.Fatalf("verify failed")
			}
		}
	})
}
