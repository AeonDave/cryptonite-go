package hpke_test

import (
	"crypto/rand"
	"testing"

	"github.com/AeonDave/cryptonite-go/hpke"
)

func makeBytes(length int, seed byte) []byte {
	buf := make([]byte, length)
	for i := range buf {
		buf[i] = seed + byte(i)
	}
	return buf
}

func BenchmarkHPKE(b *testing.B) {
	suite := hpke.SuiteX25519ChaCha20
	recipientPub, recipientPriv, err := hpke.GenerateKeyPair(rand.Reader, suite)
	if err != nil {
		b.Fatalf("keygen failed: %v", err)
	}
	info := []byte("info")
	aad := []byte("aad")
	pt := makeBytes(1024, 0x41)

	b.Run("SetupBaseSender", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, _, err := hpke.SetupBaseSender(rand.Reader, suite, recipientPub, info); err != nil {
				b.Fatalf("setup sender failed: %v", err)
			}
		}
	})

	enc, senderCtx, err := hpke.SetupBaseSender(rand.Reader, suite, recipientPub, info)
	if err != nil {
		b.Fatalf("setup sender failed: %v", err)
	}

	b.Run("SetupBaseReceiver", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := hpke.SetupBaseReceiver(suite, enc, recipientPriv, info); err != nil {
				b.Fatalf("setup receiver failed: %v", err)
			}
		}
	})

	if _, err := hpke.SetupBaseReceiver(suite, enc, recipientPriv, info); err != nil {
		b.Fatalf("setup receiver failed: %v", err)
	}

	b.Run("Seal", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(pt)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := senderCtx.Seal(aad, pt); err != nil {
				b.Fatalf("seal failed: %v", err)
			}
		}
	})

	b.Run("Seal/Open RoundTrip", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(pt)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			enc, sender, err := hpke.SetupBaseSender(rand.Reader, suite, recipientPub, info)
			if err != nil {
				b.Fatalf("setup sender failed: %v", err)
			}
			receiver, err := hpke.SetupBaseReceiver(suite, enc, recipientPriv, info)
			if err != nil {
				b.Fatalf("setup receiver failed: %v", err)
			}
			ct, err := sender.Seal(aad, pt)
			if err != nil {
				b.Fatalf("seal failed: %v", err)
			}
			if _, err := receiver.Open(aad, ct); err != nil {
				b.Fatalf("open failed: %v", err)
			}
			sender.Destroy()
			receiver.Destroy()
		}
	})
}
