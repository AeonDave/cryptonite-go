package aead_test

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/AeonDave/cryptonite-go/aead"
)

func FuzzAESGCMRoundTrip(f *testing.F) {
	cipher := aead.NewAESGCM()
	f.Add([]byte("keyseed"), []byte("nonceseed"), []byte("aad"), []byte(""))
	f.Add([]byte("another key"), []byte("short"), []byte(""), []byte("message"))
	f.Fuzz(func(t *testing.T, keySeed, nonceSeed, aad, msg []byte) {
		key := deriveAESKey(keySeed)
		nonce := deriveNonce(nonceSeed)
		ct, err := cipher.Encrypt(key, nonce, aad, msg)
		if err != nil {
			t.Fatalf("encrypt failed: %v", err)
		}
		pt, err := cipher.Decrypt(key, nonce, aad, ct)
		if err != nil {
			t.Fatalf("decrypt failed: %v", err)
		}
		if !bytes.Equal(pt, msg) {
			t.Fatalf("plaintext mismatch")
		}
		if len(ct) > 0 {
			tampered := append([]byte{}, ct...)
			tampered[0] ^= 0x40
			if _, err := cipher.Decrypt(key, nonce, aad, tampered); err == nil {
				t.Fatalf("tampered ciphertext accepted")
			}
		}
	})
}

func FuzzChaCha20Poly1305RoundTrip(f *testing.F) {
	cipher := aead.NewChaCha20Poly1305()
	f.Add([]byte("seed"), []byte("nonce"), []byte("aad"), []byte("payload"))
	f.Fuzz(func(t *testing.T, keySeed, nonceSeed, aad, msg []byte) {
		key := deriveChaChaKey(keySeed)
		nonce := deriveNonce(nonceSeed)
		ct, err := cipher.Encrypt(key, nonce, aad, msg)
		if err != nil {
			t.Fatalf("encrypt failed: %v", err)
		}
		pt, err := cipher.Decrypt(key, nonce, aad, ct)
		if err != nil {
			t.Fatalf("decrypt failed: %v", err)
		}
		if !bytes.Equal(pt, msg) {
			t.Fatalf("plaintext mismatch")
		}
		if len(ct) > 0 {
			tampered := append([]byte{}, ct...)
			tampered[len(tampered)-1] ^= 0x01
			if _, err := cipher.Decrypt(key, nonce, aad, tampered); err == nil {
				t.Fatalf("tampered ciphertext accepted")
			}
		}
	})
}

func deriveAESKey(seed []byte) []byte {
	sum := sha256.Sum256(seed)
	switch sum[0] % 3 {
	case 0:
		return sum[:16]
	case 1:
		return sum[:24]
	default:
		return sum[:]
	}
}

func deriveChaChaKey(seed []byte) []byte {
	sum := sha256.Sum256(seed)
	return sum[:]
}

func deriveNonce(seed []byte) []byte {
	sum := sha256.Sum256(seed)
	return sum[:12]
}
