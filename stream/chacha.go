package stream

import (
	"encoding/binary"
	"errors"
	"math"
)

const (
	chacha20KeySize   = 32
	chacha20NonceSize = 12
	chacha20BlockSize = 64

	xchacha20KeySize   = 32
	xchacha20NonceSize = 24
)

var (
	errChaCha20InvalidKey   = errors.New("chacha20: invalid key length")
	errChaCha20InvalidNonce = errors.New("chacha20: invalid nonce length")

	errXChaCha20InvalidKey   = errors.New("xchacha20: invalid key length")
	errXChaCha20InvalidNonce = errors.New("xchacha20: invalid nonce length")

	_ Stream = (*chacha20Cipher)(nil)
	_ Stream = (*xchacha20Cipher)(nil)
)

type chacha20Cipher struct {
	initial   [16]uint32
	counter   uint32
	exhausted bool

	keystream [chacha20BlockSize]byte
	offset    int
}

// NewChaCha20 returns a ChaCha20 stream cipher implementing Stream.
func NewChaCha20(key, nonce []byte, counter uint32) (Stream, error) {
	return newChaCha20(key, nonce, counter)
}

func newChaCha20(key, nonce []byte, counter uint32) (*chacha20Cipher, error) {
	if len(key) != chacha20KeySize {
		return nil, errChaCha20InvalidKey
	}
	if len(nonce) != chacha20NonceSize {
		return nil, errChaCha20InvalidNonce
	}
	var initial [16]uint32
	initial[0] = 0x61707865
	initial[1] = 0x3320646e
	initial[2] = 0x79622d32
	initial[3] = 0x6b206574
	for i := 0; i < 8; i++ {
		initial[4+i] = binary.LittleEndian.Uint32(key[4*i:])
	}
	initial[12] = 0
	initial[13] = binary.LittleEndian.Uint32(nonce[0:4])
	initial[14] = binary.LittleEndian.Uint32(nonce[4:8])
	initial[15] = binary.LittleEndian.Uint32(nonce[8:12])
	return &chacha20Cipher{
		initial: initial,
		counter: counter,
		offset:  chacha20BlockSize,
	}, nil
}

func (c *chacha20Cipher) KeyStream(dst []byte) {
	for len(dst) > 0 {
		if c.offset == len(c.keystream) {
			c.refill()
		}
		n := copy(dst, c.keystream[c.offset:])
		c.offset += n
		dst = dst[n:]
	}
}

func (c *chacha20Cipher) XORKeyStream(dst, src []byte) {
	if len(src) != len(dst) {
		panic("chacha20: dst and src lengths differ")
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

func (c *chacha20Cipher) Reset(counter uint32) {
	c.counter = counter
	c.offset = chacha20BlockSize
	c.exhausted = false
}

func (c *chacha20Cipher) refill() {
	if c.exhausted {
		panic("chacha20: keystream exhausted")
	}
	var state [16]uint32
	copy(state[:], c.initial[:])
	state[12] = c.counter
	chacha20Block(&state, &c.keystream)
	if c.counter == math.MaxUint32 {
		c.exhausted = true
	} else {
		c.counter++
	}
	c.offset = 0
}

// ChaCha20KeySize returns the ChaCha20 key size in bytes.
func ChaCha20KeySize() int { return chacha20KeySize }

// ChaCha20NonceSize returns the ChaCha20 nonce size in bytes.
func ChaCha20NonceSize() int { return chacha20NonceSize }

type xchacha20Cipher struct {
	inner *chacha20Cipher
}

// NewXChaCha20 returns an XChaCha20 stream cipher implementing Stream.
func NewXChaCha20(key, nonce []byte, counter uint32) (Stream, error) {
	return newXChaCha20(key, nonce, counter)
}

func newXChaCha20(key, nonce []byte, counter uint32) (*xchacha20Cipher, error) {
	if len(key) != xchacha20KeySize {
		return nil, errXChaCha20InvalidKey
	}
	if len(nonce) != xchacha20NonceSize {
		return nil, errXChaCha20InvalidNonce
	}
	subKey := hChaCha20(key, nonce[:16])
	var chachaNonce [chacha20NonceSize]byte
	copy(chachaNonce[4:], nonce[16:])
	inner, err := newChaCha20(subKey[:], chachaNonce[:], counter)
	if err != nil {
		return nil, err
	}
	return &xchacha20Cipher{inner: inner}, nil
}

func (c *xchacha20Cipher) KeyStream(dst []byte) {
	c.inner.KeyStream(dst)
}

func (c *xchacha20Cipher) XORKeyStream(dst, src []byte) {
	c.inner.XORKeyStream(dst, src)
}

func (c *xchacha20Cipher) Reset(counter uint32) {
	c.inner.Reset(counter)
}

// XChaCha20KeySize returns the XChaCha20 key size in bytes.
func XChaCha20KeySize() int { return xchacha20KeySize }

// XChaCha20NonceSize returns the XChaCha20 nonce size in bytes.
func XChaCha20NonceSize() int { return xchacha20NonceSize }

func chacha20Block(state *[16]uint32, out *[chacha20BlockSize]byte) {
	working := *state
	for i := 0; i < 10; i++ {
		quarterRound(&working, 0, 4, 8, 12)
		quarterRound(&working, 1, 5, 9, 13)
		quarterRound(&working, 2, 6, 10, 14)
		quarterRound(&working, 3, 7, 11, 15)
		quarterRound(&working, 0, 5, 10, 15)
		quarterRound(&working, 1, 6, 11, 12)
		quarterRound(&working, 2, 7, 8, 13)
		quarterRound(&working, 3, 4, 9, 14)
	}
	for i := 0; i < 16; i++ {
		working[i] += state[i]
		binary.LittleEndian.PutUint32(out[4*i:], working[i])
	}
}

func hChaCha20(key, nonce []byte) [32]byte {
	var state [16]uint32
	state[0] = 0x61707865
	state[1] = 0x3320646e
	state[2] = 0x79622d32
	state[3] = 0x6b206574
	for i := 0; i < 8; i++ {
		state[4+i] = binary.LittleEndian.Uint32(key[4*i:])
	}
	state[12] = binary.LittleEndian.Uint32(nonce[0:4])
	state[13] = binary.LittleEndian.Uint32(nonce[4:8])
	state[14] = binary.LittleEndian.Uint32(nonce[8:12])
	state[15] = binary.LittleEndian.Uint32(nonce[12:16])

	working := state
	for i := 0; i < 10; i++ {
		quarterRound(&working, 0, 4, 8, 12)
		quarterRound(&working, 1, 5, 9, 13)
		quarterRound(&working, 2, 6, 10, 14)
		quarterRound(&working, 3, 7, 11, 15)
		quarterRound(&working, 0, 5, 10, 15)
		quarterRound(&working, 1, 6, 11, 12)
		quarterRound(&working, 2, 7, 8, 13)
		quarterRound(&working, 3, 4, 9, 14)
	}

	var out [32]byte
	binary.LittleEndian.PutUint32(out[0:], working[0])
	binary.LittleEndian.PutUint32(out[4:], working[1])
	binary.LittleEndian.PutUint32(out[8:], working[2])
	binary.LittleEndian.PutUint32(out[12:], working[3])
	binary.LittleEndian.PutUint32(out[16:], working[12])
	binary.LittleEndian.PutUint32(out[20:], working[13])
	binary.LittleEndian.PutUint32(out[24:], working[14])
	binary.LittleEndian.PutUint32(out[28:], working[15])
	return out
}

func quarterRound(state *[16]uint32, a, b, c, d int) {
	state[a] += state[b]
	state[d] = bitsRotateLeft(state[d]^state[a], 16)

	state[c] += state[d]
	state[b] = bitsRotateLeft(state[b]^state[c], 12)

	state[a] += state[b]
	state[d] = bitsRotateLeft(state[d]^state[a], 8)

	state[c] += state[d]
	state[b] = bitsRotateLeft(state[b]^state[c], 7)
}

func bitsRotateLeft(x uint32, k int) uint32 {
	return (x << k) | (x >> (32 - k))
}
