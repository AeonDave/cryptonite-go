package aes256

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

const (
	keySize   = 32
	blockSize = 16
)

var errInvalidKey = errors.New("aes256: invalid key length")

// Cipher wraps the standard library AES implementation configured for 256-bit keys.
type Cipher struct {
	block cipher.Block
}

// New constructs a new AES-256 cipher with the provided key.
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

// Encrypt encrypts a single AES block.
func (c *Cipher) Encrypt(dst, src []byte) {
	c.block.Encrypt(dst, src)
}

// Decrypt decrypts a single AES block.
func (c *Cipher) Decrypt(dst, src []byte) {
	c.block.Decrypt(dst, src)
}

// KeySize returns the AES-256 key size in bytes.
func KeySize() int { return keySize }

// BlockLen returns the AES block size in bytes.
func BlockLen() int { return blockSize }
