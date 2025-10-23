package stream

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"math"
)

const (
	aesCTRBlockSize = 16
	aesCTRNonceSize = 12
)

var (
	errAESCTRInvalidKey   = errors.New("aesctr: invalid key length")
	errAESCTRInvalidNonce = errors.New("aesctr: invalid nonce length")

	_ Stream = (*aesCTRCipher)(nil)
)

type aesCTRCipher struct {
	block     cipher.Block
	nonce     [aesCTRNonceSize]byte
	counter   uint32
	exhausted bool

	keystream [aesCTRBlockSize]byte
	offset    int
}

// NewAESCTR returns an AES-CTR stream cipher implementing Stream.
func NewAESCTR(key, nonce []byte, counter uint32) (Stream, error) {
	return newAESCTR(key, nonce, counter)
}

func newAESCTR(key, nonce []byte, counter uint32) (*aesCTRCipher, error) {
	switch len(key) {
	case 16, 24, 32:
	default:
		return nil, errAESCTRInvalidKey
	}
	if len(nonce) != aesCTRNonceSize {
		return nil, errAESCTRInvalidNonce
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	var n [aesCTRNonceSize]byte
	copy(n[:], nonce)
	return &aesCTRCipher{
		block:   block,
		nonce:   n,
		counter: counter,
		offset:  aesCTRBlockSize,
	}, nil
}

func (c *aesCTRCipher) KeyStream(dst []byte) {
	for len(dst) > 0 {
		if c.offset == len(c.keystream) {
			c.refill()
		}
		n := copy(dst, c.keystream[c.offset:])
		c.offset += n
		dst = dst[n:]
	}
}

func (c *aesCTRCipher) XORKeyStream(dst, src []byte) {
	if len(src) != len(dst) {
		panic("aesctr: dst and src lengths differ")
	}
	for len(src) > 0 {
		if c.offset == len(c.keystream) {
			c.refill()
		}
		remain := len(c.keystream) - c.offset
		n := len(src)
		if n > remain {
			n = remain
		}
		copy(dst[:n], src[:n])
		keystream := c.keystream[c.offset : c.offset+n]
		for i := 0; i < n; i++ {
			dst[i] ^= keystream[i]
		}
		c.offset += n
		dst = dst[n:]
		src = src[n:]
	}
}

func (c *aesCTRCipher) Reset(counter uint32) {
	c.counter = counter
	c.offset = aesCTRBlockSize
	c.exhausted = false
}

func (c *aesCTRCipher) refill() {
	if c.exhausted {
		panic("aesctr: keystream exhausted")
	}
	var counterBlock [aesCTRBlockSize]byte
	copy(counterBlock[:aesCTRNonceSize], c.nonce[:])
	binary.BigEndian.PutUint32(counterBlock[aesCTRNonceSize:], c.counter)
	c.block.Encrypt(c.keystream[:], counterBlock[:])
	if c.counter == math.MaxUint32 {
		c.exhausted = true
	} else {
		c.counter++
	}
	c.offset = 0
}

// AESCTRNonceSize returns the AES-CTR nonce size in bytes.
func AESCTRNonceSize() int { return aesCTRNonceSize }
