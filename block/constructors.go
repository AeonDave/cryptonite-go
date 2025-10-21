package block

import (
	"cryptonite-go/block/aes128"
	"cryptonite-go/block/aes256"
)

var (
	_ Cipher = (*aes128.Cipher)(nil)
	_ Cipher = (*aes256.Cipher)(nil)
)

// NewAES128 returns an AES-128 block cipher implementing Cipher.
func NewAES128(key []byte) (Cipher, error) {
	return aes128.New(key)
}

// NewAES256 returns an AES-256 block cipher implementing Cipher.
func NewAES256(key []byte) (Cipher, error) {
	return aes256.New(key)
}
