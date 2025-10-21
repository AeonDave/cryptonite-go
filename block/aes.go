package block

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

const (
	aes128KeySize = 16
	aes256KeySize = 32
	aesBlockSize  = 16
)

var (
	errInvalidAES128Key = errors.New("aes128: invalid key length")
	errInvalidAES256Key = errors.New("aes256: invalid key length")
)

var (
	_ Cipher = (*aes128Cipher)(nil)
	_ Cipher = (*aes256Cipher)(nil)
)

type aes128Cipher struct {
	block cipher.Block
}

type aes256Cipher struct {
	block cipher.Block
}

func newAES128Cipher(key []byte) (*aes128Cipher, error) {
	if len(key) != aes128KeySize {
		return nil, errInvalidAES128Key
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &aes128Cipher{block: b}, nil
}

func newAES256Cipher(key []byte) (*aes256Cipher, error) {
	if len(key) != aes256KeySize {
		return nil, errInvalidAES256Key
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &aes256Cipher{block: b}, nil
}

func (c *aes128Cipher) BlockSize() int {
	return c.block.BlockSize()
}

func (c *aes128Cipher) Encrypt(dst, src []byte) {
	c.block.Encrypt(dst, src)
}

func (c *aes128Cipher) Decrypt(dst, src []byte) {
	c.block.Decrypt(dst, src)
}

func (c *aes256Cipher) BlockSize() int {
	return c.block.BlockSize()
}

func (c *aes256Cipher) Encrypt(dst, src []byte) {
	c.block.Encrypt(dst, src)
}

func (c *aes256Cipher) Decrypt(dst, src []byte) {
	c.block.Decrypt(dst, src)
}

// AES128KeySize returns the AES-128 key size in bytes.
func AES128KeySize() int { return aes128KeySize }

// AES256KeySize returns the AES-256 key size in bytes.
func AES256KeySize() int { return aes256KeySize }

// AESBlockSize returns the AES block size in bytes.
func AESBlockSize() int { return aesBlockSize }

// NewAES128 returns an AES-128 block cipher implementing Cipher.
func NewAES128(key []byte) (Cipher, error) {
	return newAES128Cipher(key)
}

// NewAES256 returns an AES-256 block cipher implementing Cipher.
func NewAES256(key []byte) (Cipher, error) {
	return newAES256Cipher(key)
}
