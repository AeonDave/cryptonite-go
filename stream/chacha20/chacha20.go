package chacha20

import (
	"encoding/binary"
	"errors"
	"math"
)

const (
	keySize   = 32
	nonceSize = 12
	blockSize = 64
)

var (
	errInvalidKey   = errors.New("chacha20: invalid key length")
	errInvalidNonce = errors.New("chacha20: invalid nonce length")
)

// Cipher implements the ChaCha20 stream cipher (IETF variant).
//
// It can produce either raw keystream bytes or XOR encrypted/decrypted data.
type Cipher struct {
	initial   [16]uint32
	counter   uint32
	exhausted bool

	keystream [blockSize]byte
	offset    int
}

// New returns a ChaCha20 cipher configured with the given key, nonce, and
// initial block counter.
func New(key, nonce []byte, counter uint32) (*Cipher, error) {
	if len(key) != keySize {
		return nil, errInvalidKey
	}
	if len(nonce) != nonceSize {
		return nil, errInvalidNonce
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
	return &Cipher{
		initial: initial,
		counter: counter,
		offset:  blockSize,
	}, nil
}

// KeyStream writes len(dst) keystream bytes into dst.
func (c *Cipher) KeyStream(dst []byte) {
	for len(dst) > 0 {
		if c.offset == len(c.keystream) {
			c.refill()
		}
		n := copy(dst, c.keystream[c.offset:])
		c.offset += n
		dst = dst[n:]
	}
}

// XORKeyStream XORs src with the keystream, placing the result into dst.
func (c *Cipher) XORKeyStream(dst, src []byte) {
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
		// Copy handles overlapping dst and src.
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

func (c *Cipher) refill() {
	if c.exhausted {
		panic("chacha20: keystream exhausted")
	}
	var state [16]uint32
	copy(state[:], c.initial[:])
	state[12] = c.counter
	chachaBlock(&state, &c.keystream)
	if c.counter == math.MaxUint32 {
		c.exhausted = true
	} else {
		c.counter++
	}
	c.offset = 0
}

func chachaBlock(state *[16]uint32, out *[blockSize]byte) {
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

// Reset rewinds the cipher to the initial state using the provided block
// counter.
func (c *Cipher) Reset(counter uint32) {
	c.counter = counter
	c.offset = blockSize
	c.exhausted = false
}

// KeySize returns the ChaCha20 key size in bytes.
func KeySize() int { return keySize }

// NonceSize returns the ChaCha20 nonce size in bytes.
func NonceSize() int { return nonceSize }
