package aead

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

const (
	aesGCMTagSize   = 16
	aesGCMNonceSize = 12
)

// aesGCM implements the Aead interface using AES in GCM mode.
type aesGCM struct{}

// NewAESGCM returns a zero-allocation AEAD cipher instance.
func NewAESGCM() Aead { return aesGCM{} }

func (aesGCM) Encrypt(key, nonce, ad, plaintext []byte) ([]byte, error) {
	if !validAESKeyLen(len(key)) {
		return nil, errors.New("aesgcm: invalid key size")
	}
	if len(nonce) != aesGCMNonceSize {
		return nil, errors.New("aesgcm: invalid nonce size")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	// Seal returns ciphertext || tag (16 bytes) appended.
	return gcm.Seal(nil, nonce, plaintext, ad), nil
}

func (aesGCM) Decrypt(key, nonce, ad, ciphertextAndTag []byte) ([]byte, error) {
	if !validAESKeyLen(len(key)) {
		return nil, errors.New("aesgcm: invalid key size")
	}
	if len(nonce) != aesGCMNonceSize {
		return nil, errors.New("aesgcm: invalid nonce size")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	// Open expects ciphertext || tag in a single slice.
	return gcm.Open(nil, nonce, ciphertextAndTag, ad)
}

func validAESKeyLen(n int) bool { return n == 16 || n == 24 || n == 32 }
