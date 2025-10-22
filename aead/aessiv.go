package aead

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"errors"
)

const aesSIVTagSize = 16

type aesSIV struct {
	keyLen int
}

// MultiAssociatedData exposes AES-SIV helpers that accept an arbitrary number
// of associated data components in addition to the optional nonce. This mirrors
// the SIV construction defined in RFC 5297 where the nonce is treated as the
// first associated string and additional components may follow.
type MultiAssociatedData interface {
	EncryptWithAssociatedData(key, nonce []byte, ad [][]byte, plaintext []byte) ([]byte, error)
	DecryptWithAssociatedData(key, nonce []byte, ad [][]byte, ciphertextAndTag []byte) ([]byte, error)
}

// NewAES128SIV returns an AES-SIV AEAD instance that expects 32-byte keys.
// The first half of the key is used for S2V (CMAC), and the second half for CTR.
func NewAES128SIV() Aead { return aesSIV{keyLen: 32} }

// NewAES256SIV returns an AES-SIV AEAD instance that expects 64-byte keys.
// The first half of the key is used for S2V (CMAC), and the second half for CTR.
func NewAES256SIV() Aead { return aesSIV{keyLen: 64} }

func (a aesSIV) Encrypt(key, nonce, ad, plaintext []byte) ([]byte, error) {
	var adList [][]byte
	if ad != nil {
		adList = append(adList, ad)
	}
	return a.encryptWithAssociatedData(key, nonce, adList, plaintext)
}

func (a aesSIV) Decrypt(key, nonce, ad, ciphertextAndTag []byte) ([]byte, error) {
	var adList [][]byte
	if ad != nil {
		adList = append(adList, ad)
	}
	return a.decryptWithAssociatedData(key, nonce, adList, ciphertextAndTag)
}

// EncryptWithAssociatedData accepts an arbitrary number of associated data
// components. The nonce, when provided, is treated as the final associated
// string before the plaintext, matching Section 3 of RFC 5297.
func (a aesSIV) EncryptWithAssociatedData(key, nonce []byte, ad [][]byte, plaintext []byte) ([]byte, error) {
	return a.encryptWithAssociatedData(key, nonce, ad, plaintext)
}

// DecryptWithAssociatedData mirrors EncryptWithAssociatedData for decryption.
func (a aesSIV) DecryptWithAssociatedData(key, nonce []byte, ad [][]byte, ciphertextAndTag []byte) ([]byte, error) {
	return a.decryptWithAssociatedData(key, nonce, ad, ciphertextAndTag)
}

func (a aesSIV) encryptWithAssociatedData(key, nonce []byte, ad [][]byte, plaintext []byte) ([]byte, error) {
	if len(key) != a.keyLen {
		return nil, errors.New("aessiv: invalid key size")
	}
	macKey := key[:len(key)/2]
	encKey := key[len(key)/2:]
	synthetic, err := computeS2V(macKey, nonce, ad, plaintext)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	var counter [aesSIVTagSize]byte
	copy(counter[:], synthetic[:])
	clearSIVCounterBits(counter[:])
	stream := cipher.NewCTR(block, counter[:])
	result := make([]byte, len(plaintext)+aesSIVTagSize)
	copy(result[:aesSIVTagSize], synthetic[:])
	if len(plaintext) > 0 {
		stream.XORKeyStream(result[aesSIVTagSize:], plaintext)
	}
	return result, nil
}

func (a aesSIV) decryptWithAssociatedData(key, nonce []byte, ad [][]byte, ciphertextAndTag []byte) ([]byte, error) {
	if len(key) != a.keyLen {
		return nil, errors.New("aessiv: invalid key size")
	}
	if len(ciphertextAndTag) < aesSIVTagSize {
		return nil, errors.New("aessiv: ciphertext too short")
	}
	macKey := key[:len(key)/2]
	encKey := key[len(key)/2:]
	tag := ciphertextAndTag[:aesSIVTagSize]
	ciphertext := ciphertextAndTag[aesSIVTagSize:]
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	var counter [aesSIVTagSize]byte
	copy(counter[:], tag)
	clearSIVCounterBits(counter[:])
	stream := cipher.NewCTR(block, counter[:])
	plaintext := make([]byte, len(ciphertext))
	if len(ciphertext) > 0 {
		stream.XORKeyStream(plaintext, ciphertext)
	}
	expected, err := computeS2V(macKey, nonce, ad, plaintext)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(expected[:], tag) != 1 {
		return nil, errors.New("aessiv: authentication failed")
	}
	return plaintext, nil
}

func computeS2V(macKey, nonce []byte, ad [][]byte, plaintext []byte) ([aesSIVTagSize]byte, error) {
	components := make([][]byte, 0, len(ad)+1)
	if len(ad) > 0 {
		components = append(components, ad...)
	}
	if nonce != nil {
		components = append(components, nonce)
	}
	return s2v(macKey, components, plaintext)
}

func s2v(macKey []byte, ad [][]byte, plaintext []byte) ([aesSIVTagSize]byte, error) {
	cm, err := newCMAC(macKey)
	if err != nil {
		return [aesSIVTagSize]byte{}, err
	}
	var zero [aesSIVTagSize]byte
	d := cm.sum(zero[:])
	for _, s := range ad {
		t := cm.sum(s)
		d = dblBlock16(d)
		d = xorBlock16(d, t)
	}
	if len(plaintext) >= aesSIVTagSize {
		var mask [aesSIVTagSize]byte = d
		return cm.sumWithLastMask(plaintext, mask), nil
	}
	dbl := dblBlock16(d)
	var buf [aesSIVTagSize]byte
	copy(buf[:], plaintext)
	buf[len(plaintext)] = 0x80
	xorBytes(buf[:], dbl[:])
	return cm.sum(buf[:]), nil
}

type cmacState struct {
	block cipher.Block
	k1    [aesSIVTagSize]byte
	k2    [aesSIVTagSize]byte
}

func newCMAC(key []byte) (*cmacState, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	var l [aesSIVTagSize]byte
	block.Encrypt(l[:], l[:])
	k1 := dblBlock16(l)
	k2 := dblBlock16(k1)
	return &cmacState{block: block, k1: k1, k2: k2}, nil
}

func (c *cmacState) sum(msg []byte) [aesSIVTagSize]byte {
	var state [aesSIVTagSize]byte
	n := len(msg)
	if n == 0 {
		var last [aesSIVTagSize]byte
		last[0] = 0x80
		xorBytes(last[:], c.k2[:])
		for i := 0; i < aesSIVTagSize; i++ {
			state[i] ^= last[i]
		}
		c.block.Encrypt(state[:], state[:])
		return state
	}
	blocks := (n + aesSIVTagSize - 1) / aesSIVTagSize
	for i := 0; i < blocks-1; i++ {
		offset := i * aesSIVTagSize
		for j := 0; j < aesSIVTagSize; j++ {
			state[j] ^= msg[offset+j]
		}
		c.block.Encrypt(state[:], state[:])
	}
	offset := (blocks - 1) * aesSIVTagSize
	var last [aesSIVTagSize]byte
	if n%aesSIVTagSize == 0 {
		copy(last[:], msg[offset:offset+aesSIVTagSize])
		xorBytes(last[:], c.k1[:])
	} else {
		copy(last[:], msg[offset:])
		last[n-offset] = 0x80
		xorBytes(last[:], c.k2[:])
	}
	for i := 0; i < aesSIVTagSize; i++ {
		state[i] ^= last[i]
	}
	c.block.Encrypt(state[:], state[:])
	return state
}

func (c *cmacState) sumWithLastMask(msg []byte, mask [aesSIVTagSize]byte) [aesSIVTagSize]byte {
	if len(msg) < aesSIVTagSize {
		return c.sum(msg)
	}
	buf := make([]byte, len(msg))
	copy(buf, msg)
	offset := len(buf) - aesSIVTagSize
	xorBytes(buf[offset:], mask[:])
	return c.sum(buf)
}

func dblBlock16(in [aesSIVTagSize]byte) [aesSIVTagSize]byte {
	var out [aesSIVTagSize]byte
	msb := in[0] >> 7
	var carry byte
	for i := aesSIVTagSize - 1; i >= 0; i-- {
		b := in[i]
		out[i] = (b << 1) | carry
		carry = b >> 7
	}
	if msb != 0 {
		out[aesSIVTagSize-1] ^= 0x87
	}
	return out
}

func xorBlock16(a, b [aesSIVTagSize]byte) [aesSIVTagSize]byte {
	for i := range a {
		a[i] ^= b[i]
	}
	return a
}

func xorBytes(dst []byte, src []byte) {
	for i := range dst {
		dst[i] ^= src[i]
	}
}

func clearSIVCounterBits(counter []byte) {
	if len(counter) != aesSIVTagSize {
		return
	}
	counter[8] &= 0x7f
	counter[12] &= 0x7f
}
