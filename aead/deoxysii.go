package aead

import (
	"errors"

	"cryptonite-go/internal/deoxysii"
)

type deoxysII128 struct{}

// NewDeoxysII128 returns an AEAD based on Deoxys-II-256-128 (NIST LwC finalist).
// Keys are 32 bytes, nonces are 15 bytes, and the authentication tag is 16 bytes.
func NewDeoxysII128() Aead { return deoxysII128{} }

func (deoxysII128) Encrypt(key, nonce, ad, plaintext []byte) ([]byte, error) {
	switch {
	case len(key) != deoxysii.KeySize:
		return nil, errors.New("deoxysii128: invalid key size")
	case len(nonce) != deoxysii.NonceSize:
		return nil, errors.New("deoxysii128: invalid nonce size")
	}
	return deoxysii.Seal(key, nonce, ad, plaintext)
}

func (deoxysII128) Decrypt(key, nonce, ad, ciphertextAndTag []byte) ([]byte, error) {
	switch {
	case len(key) != deoxysii.KeySize:
		return nil, errors.New("deoxysii128: invalid key size")
	case len(nonce) != deoxysii.NonceSize:
		return nil, errors.New("deoxysii128: invalid nonce size")
	}
	return deoxysii.Open(key, nonce, ad, ciphertextAndTag)
}
