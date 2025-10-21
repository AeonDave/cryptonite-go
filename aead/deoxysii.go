package aead

import "errors"

type deoxysII128 struct{}

// NewDeoxysII128 returns a placeholder implementation for Deoxys-II-128.
// TODO: add full Deoxys-II support (NIST LwC finalist).
func NewDeoxysII128() Aead { return deoxysII128{} }

func (deoxysII128) Encrypt(key, nonce, ad, plaintext []byte) ([]byte, error) {
	if len(key) != 16 {
		return nil, errors.New("deoxysii128: invalid key size")
	}
	return nil, errors.New("deoxysii128: not implemented yet")
}

func (deoxysII128) Decrypt(key, nonce, ad, ciphertextAndTag []byte) ([]byte, error) {
	if len(key) != 16 {
		return nil, errors.New("deoxysii128: invalid key size")
	}
	return nil, errors.New("deoxysii128: not implemented yet")
}
