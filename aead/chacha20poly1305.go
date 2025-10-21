package aead

import (
	"crypto/subtle"
	"errors"

	"github.com/AeonDave/cryptonite-go/internal/chacha20"
	"github.com/AeonDave/cryptonite-go/internal/poly1305"
)

const (
	chacha20Poly1305KeySize   = 32
	chacha20Poly1305NonceSize = 12
	chacha20Poly1305TagSize   = 16
)

// chaCha20Poly1305 implements the Aead interface using the ChaCha20-Poly1305 construction.
type chaCha20Poly1305 struct{}

// NewChaCha20Poly1305 returns a zero-allocation AEAD cipher instance.
func NewChaCha20Poly1305() Aead {
	return chaCha20Poly1305{}
}

func (chaCha20Poly1305) Encrypt(key, nonce, ad, plaintext []byte) ([]byte, error) {
	if len(key) != chacha20Poly1305KeySize {
		return nil, errors.New("chacha20poly1305: invalid key size")
	}
	if len(nonce) != chacha20Poly1305NonceSize {
		return nil, errors.New("chacha20poly1305: invalid nonce size")
	}

	var polyKey [32]byte
	chacha20.DerivePoly1305Key(&polyKey, key, nonce)

	ciphertext := make([]byte, len(plaintext))
	chacha20.XORKeyStream(ciphertext, plaintext, key, nonce, 1)

	tag := poly1305.Tag(polyKey, ad, ciphertext)

	result := make([]byte, len(ciphertext)+chacha20Poly1305TagSize)
	copy(result, ciphertext)
	copy(result[len(ciphertext):], tag[:])
	return result, nil
}

func (chaCha20Poly1305) Decrypt(key, nonce, ad, ciphertextAndTag []byte) ([]byte, error) {
	if len(key) != chacha20Poly1305KeySize {
		return nil, errors.New("chacha20poly1305: invalid key size")
	}
	if len(nonce) != chacha20Poly1305NonceSize {
		return nil, errors.New("chacha20poly1305: invalid nonce size")
	}
	if len(ciphertextAndTag) < chacha20Poly1305TagSize {
		return nil, errors.New("chacha20poly1305: ciphertext too short")
	}

	ciphertextLen := len(ciphertextAndTag) - chacha20Poly1305TagSize
	ciphertext := ciphertextAndTag[:ciphertextLen]
	receivedTag := ciphertextAndTag[ciphertextLen:]

	var polyKey [32]byte
	chacha20.DerivePoly1305Key(&polyKey, key, nonce)

	expectedTag := poly1305.Tag(polyKey, ad, ciphertext)
	if subtle.ConstantTimeCompare(receivedTag, expectedTag[:]) != 1 {
		return nil, errors.New("chacha20poly1305: authentication failed")
	}

	plaintext := make([]byte, len(ciphertext))
	chacha20.XORKeyStream(plaintext, ciphertext, key, nonce, 1)
	return plaintext, nil
}
