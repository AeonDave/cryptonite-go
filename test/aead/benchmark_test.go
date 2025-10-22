package aead_test

import (
	"testing"

	"github.com/AeonDave/cryptonite-go/aead"
)

func benchmarkAeadEncrypt(b *testing.B, ctor func() aead.Aead, key, nonce, ad, plaintext []byte) {
	b.Helper()
	cipher := ctor()
	b.ReportAllocs()
	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := cipher.Encrypt(key, nonce, ad, plaintext); err != nil {
			b.Fatalf("encrypt failed: %v", err)
		}
	}
}

func benchmarkAeadDecrypt(b *testing.B, ctor func() aead.Aead, key, nonce, ad, plaintext []byte) {
	b.Helper()
	cipher := ctor()
	ciphertext, err := cipher.Encrypt(key, nonce, ad, plaintext)
	if err != nil {
		b.Fatalf("encrypt setup failed: %v", err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := cipher.Decrypt(key, nonce, ad, ciphertext); err != nil {
			b.Fatalf("decrypt failed: %v", err)
		}
	}
}

func makeBytes(length int, seed byte) []byte {
	buf := make([]byte, length)
	for i := range buf {
		buf[i] = seed + byte(i)
	}
	return buf
}

func BenchmarkAEADEncrypt(b *testing.B) {
	ad := makeBytes(32, 0x03)
	msg := makeBytes(1024, 0x11)
	specs := []struct {
		name  string
		key   []byte
		nonce []byte
		ctor  func() aead.Aead
	}{
		{"ASCON128a", makeBytes(16, 0x01), makeBytes(16, 0x02), aead.NewAscon128},
		{"ASCON80pq", makeBytes(20, 0x01), makeBytes(16, 0x02), aead.NewAscon80pq},
		{"GiftCofb", makeBytes(16, 0x01), makeBytes(16, 0x02), aead.NewGiftCofb},
		{"SkinnyAeadM1", makeBytes(16, 0x01), makeBytes(16, 0x02), aead.NewSkinnyAead},
		{"XoodyakEncrypt", makeBytes(16, 0x01), makeBytes(16, 0x02), aead.NewXoodyak},
		{"ChaCha20Poly1305", makeBytes(32, 0x01), makeBytes(12, 0x02), aead.NewChaCha20Poly1305},
		{"XChaCha20Poly1305", makeBytes(32, 0x01), makeBytes(24, 0x02), aead.NewXChaCha20Poly1305},
		{"AESGCM", makeBytes(32, 0x01), makeBytes(12, 0x02), aead.NewAESGCM},
		{"AESGCMSIV", makeBytes(32, 0x01), makeBytes(12, 0x02), aead.NewAesGcmSiv},
		{"AES128SIV", makeBytes(32, 0x01), nil, aead.NewAES128SIV},
		{"AES256SIV", makeBytes(64, 0x01), nil, aead.NewAES256SIV},
		{"DeoxysII128", makeBytes(32, 0x01), makeBytes(15, 0x02), aead.NewDeoxysII128},
	}
	for _, spec := range specs {
		spec := spec
		nonce := spec.nonce
		if nonce == nil {
			nonce = make([]byte, 0)
		}
		b.Run(spec.name, func(b *testing.B) {
			benchmarkAeadEncrypt(b, spec.ctor, spec.key, nonce, ad, msg)
		})
	}
}

func BenchmarkAEADDecrypt(b *testing.B) {
	ad := makeBytes(32, 0x05)
	msg := makeBytes(1024, 0x17)
	specs := []struct {
		name  string
		key   []byte
		nonce []byte
		ctor  func() aead.Aead
	}{
		{"ASCON128a", makeBytes(16, 0x01), makeBytes(16, 0x02), aead.NewAscon128},
		{"ASCON80pq", makeBytes(20, 0x01), makeBytes(16, 0x02), aead.NewAscon80pq},
		{"GiftCofb", makeBytes(16, 0x01), makeBytes(16, 0x02), aead.NewGiftCofb},
		{"SkinnyAeadM1", makeBytes(16, 0x01), makeBytes(16, 0x02), aead.NewSkinnyAead},
		{"XoodyakEncrypt", makeBytes(16, 0x01), makeBytes(16, 0x02), aead.NewXoodyak},
		{"ChaCha20Poly1305", makeBytes(32, 0x01), makeBytes(12, 0x02), aead.NewChaCha20Poly1305},
		{"XChaCha20Poly1305", makeBytes(32, 0x01), makeBytes(24, 0x02), aead.NewXChaCha20Poly1305},
		{"AESGCM", makeBytes(32, 0x01), makeBytes(12, 0x02), aead.NewAESGCM},
		{"AESGCMSIV", makeBytes(32, 0x01), makeBytes(12, 0x02), aead.NewAesGcmSiv},
		{"AES128SIV", makeBytes(32, 0x01), nil, aead.NewAES128SIV},
		{"AES256SIV", makeBytes(64, 0x01), nil, aead.NewAES256SIV},
		{"DeoxysII128", makeBytes(32, 0x01), makeBytes(15, 0x02), aead.NewDeoxysII128},
	}
	for _, spec := range specs {
		spec := spec
		nonce := spec.nonce
		if nonce == nil {
			nonce = make([]byte, 0)
		}
		b.Run(spec.name, func(b *testing.B) {
			benchmarkAeadDecrypt(b, spec.ctor, spec.key, nonce, ad, msg)
		})
	}
}
