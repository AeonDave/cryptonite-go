package aes128

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

const (
	keySize   = 16
	blockSize = 16
)

var errInvalidKey = errors.New("aes128: invalid key length")

// Cipher is a thin wrapper around the standard library AES implementation.
type Cipher struct {
	block cipher.Block
}

// New constructs a new AES-128 cipher with the provided key.
func New(key []byte) (*Cipher, error) {
	if len(key) != keySize {
		return nil, errInvalidKey
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &Cipher{block: b}, nil
}

// BlockSize returns AES's 16-byte block size.
func (c *Cipher) BlockSize() int {
	return c.block.BlockSize()
}

// Encrypt encrypts a single 16-byte block.
func (c *Cipher) Encrypt(dst, src []byte) {
	c.block.Encrypt(dst, src)
}

// Decrypt decrypts a single 16-byte block.
func (c *Cipher) Decrypt(dst, src []byte) {
	c.block.Decrypt(dst, src)
}

// KeySize returns the AES-128 key size in bytes.
func KeySize() int { return keySize }

// BlockLen returns the AES block size in bytes.
func BlockLen() int { return blockSize }
