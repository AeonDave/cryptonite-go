package xchacha20

import (
	"encoding/binary"
	"errors"

	"cryptonite-go/stream/chacha20"
)

const (
	keySize   = 32
	nonceSize = 24
)

var (
	errInvalidKey   = errors.New("xchacha20: invalid key length")
	errInvalidNonce = errors.New("xchacha20: invalid nonce length")
)

// Cipher implements the XChaCha20 stream cipher using the construction from
// draft-irtf-cfrg-xchacha-01.
type Cipher struct {
	inner *chacha20.Cipher
}

// New derives a subkey using HChaCha20 and returns a ChaCha20 instance seeded
// with the derived key and nonce.
func New(key, nonce []byte, counter uint32) (*Cipher, error) {
	if len(key) != keySize {
		return nil, errInvalidKey
	}
	if len(nonce) != nonceSize {
		return nil, errInvalidNonce
	}
	subKey := hChaCha20(key, nonce[:16])
	var chachaNonce [12]byte
	copy(chachaNonce[4:], nonce[16:])
	inner, err := chacha20.New(subKey[:], chachaNonce[:], counter)
	if err != nil {
		return nil, err
	}
	return &Cipher{inner: inner}, nil
}

// KeyStream writes len(dst) keystream bytes into dst.
func (c *Cipher) KeyStream(dst []byte) {
	c.inner.KeyStream(dst)
}

// XORKeyStream XORs src with the keystream, writing the result to dst.
func (c *Cipher) XORKeyStream(dst, src []byte) {
	c.inner.XORKeyStream(dst, src)
}

// Reset rewinds the cipher to the given block counter.
func (c *Cipher) Reset(counter uint32) {
	c.inner.Reset(counter)
}

// KeySize returns the XChaCha20 key size in bytes.
func KeySize() int { return keySize }

// NonceSize returns the XChaCha20 nonce size in bytes.
func NonceSize() int { return nonceSize }

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
