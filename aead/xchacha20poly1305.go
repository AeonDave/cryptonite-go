package aead

import (
	"crypto/subtle"
	"errors"

	"github.com/AeonDave/cryptonite-go/internal/chacha20"
	"github.com/AeonDave/cryptonite-go/internal/poly1305"
)

const (
	xchacha20Poly1305KeySize   = 32
	xchacha20Poly1305NonceSize = 24
	xchacha20Poly1305TagSize   = 16
)

// xChaCha20Poly1305 implements AEAD using XChaCha20-Poly1305 (IETF construction).
// It derives a subkey using HChaCha20 and uses a 12-byte nonce for the ChaCha20 core.
type xChaCha20Poly1305 struct{}

// NewXChaCha20Poly1305 returns a zero-allocation AEAD cipher instance.
func NewXChaCha20Poly1305() Aead { return xChaCha20Poly1305{} }

func (xChaCha20Poly1305) Encrypt(key, nonce, ad, plaintext []byte) ([]byte, error) {
	if len(key) != xchacha20Poly1305KeySize {
		return nil, errors.New("xchacha20poly1305: invalid key size")
	}
	if len(nonce) != xchacha20Poly1305NonceSize {
		return nil, errors.New("xchacha20poly1305: invalid nonce size")
	}

	// Derive subkey and 12-byte nonce via HChaCha20
	var subkey [32]byte
	chacha20.HChaCha20(&subkey, key, nonce[:16])
	var nonce12 [12]byte
	// Per XChaCha20 spec: nonce12 = 0x00000000 || nonce[16:24]
	copy(nonce12[4:], nonce[16:])

	var polyKey [32]byte
	chacha20.DerivePoly1305Key(&polyKey, subkey[:], nonce12[:])

	ciphertext := make([]byte, len(plaintext))
	chacha20.XORKeyStream(ciphertext, plaintext, subkey[:], nonce12[:], 1)

	tag := poly1305.Tag(polyKey, ad, ciphertext)

	result := make([]byte, len(ciphertext)+xchacha20Poly1305TagSize)
	copy(result, ciphertext)
	copy(result[len(ciphertext):], tag[:])
	return result, nil
}

func (xChaCha20Poly1305) Decrypt(key, nonce, ad, ciphertextAndTag []byte) ([]byte, error) {
	if len(key) != xchacha20Poly1305KeySize {
		return nil, errors.New("xchacha20poly1305: invalid key size")
	}
	if len(nonce) != xchacha20Poly1305NonceSize {
		return nil, errors.New("xchacha20poly1305: invalid nonce size")
	}
	if len(ciphertextAndTag) < xchacha20Poly1305TagSize {
		return nil, errors.New("xchacha20poly1305: ciphertext too short")
	}

	// Derive subkey and 12-byte nonce via HChaCha20
	var subkey [32]byte
	chacha20.HChaCha20(&subkey, key, nonce[:16])
	var nonce12 [12]byte
	copy(nonce12[4:], nonce[16:])

	ctLen := len(ciphertextAndTag) - xchacha20Poly1305TagSize
	ct := ciphertextAndTag[:ctLen]
	receivedTag := ciphertextAndTag[ctLen:]

	var polyKey [32]byte
	chacha20.DerivePoly1305Key(&polyKey, subkey[:], nonce12[:])
	expectedTag := poly1305.Tag(polyKey, ad, ct)
	if subtle.ConstantTimeCompare(receivedTag, expectedTag[:]) != 1 {
		return nil, errors.New("xchacha20poly1305: authentication failed")
	}

	pt := make([]byte, len(ct))
	chacha20.XORKeyStream(pt, ct, subkey[:], nonce12[:], 1)
	return pt, nil
}
