package aead

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

const (
	giftCOFBKeySize   = 16
	giftCOFBNonceSize = 16
	giftCOFBTagSize   = 16
)

type giftCofb struct{}

// NewGiftCofb returns an AEAD implementation of the GIFT-COFB algorithm.
func NewGiftCofb() Aead {
	return giftCofb{}
}

func (giftCofb) Encrypt(key, nonce, ad, plaintext []byte) ([]byte, error) {
	if len(key) != giftCOFBKeySize {
		return nil, errors.New("giftcofb: invalid key size")
	}
	if len(nonce) != giftCOFBNonceSize {
		return nil, errors.New("giftcofb: invalid nonce size")
	}

	out := make([]byte, len(plaintext)+giftCOFBTagSize)
	ciphertext := out[:len(plaintext)]
	tag := out[len(plaintext):]

	y, input, offset := giftcofbInitState(key, nonce, ad, len(plaintext) == 0)

	m := plaintext
	outPos := 0
	for len(m) > giftBlockSize {
		giftDoubleHalfBlock(&offset, &offset)
		giftPho(&y, m[:giftBlockSize], &input, ciphertext[outPos:outPos+giftBlockSize], giftBlockSize)
		giftXorTopBar(&input, &input, &offset)
		giftEncryptBlock(&y, key, input[:])
		m = m[giftBlockSize:]
		outPos += giftBlockSize
	}

	if len(plaintext) > 0 {
		giftTripleHalfBlock(&offset, &offset)
		if len(m)%giftBlockSize != 0 {
			giftTripleHalfBlock(&offset, &offset)
		}
		giftPho(&y, m, &input, ciphertext[outPos:outPos+len(m)], len(m))
		outPos += len(m)
		giftXorTopBar(&input, &input, &offset)
		giftEncryptBlock(&y, key, input[:])
	}

	copy(tag, y[:giftCOFBTagSize])
	return out, nil
}

func (giftCofb) Decrypt(key, nonce, ad, ciphertextAndTag []byte) ([]byte, error) {
	if len(key) != giftCOFBKeySize {
		return nil, errors.New("giftcofb: invalid key size")
	}
	if len(nonce) != giftCOFBNonceSize {
		return nil, errors.New("giftcofb: invalid nonce size")
	}
	if len(ciphertextAndTag) < giftCOFBTagSize {
		return nil, errors.New("giftcofb: ciphertext too short")
	}

	ct := ciphertextAndTag[:len(ciphertextAndTag)-giftCOFBTagSize]
	tag := ciphertextAndTag[len(ciphertextAndTag)-giftCOFBTagSize:]

	out := make([]byte, len(ct))

	y, input, offset := giftcofbInitState(key, nonce, ad, len(ct) == 0)

	c := ct
	outPos := 0
	for len(c) > giftBlockSize {
		giftDoubleHalfBlock(&offset, &offset)
		giftPhoPrime(&y, c[:giftBlockSize], &input, out[outPos:outPos+giftBlockSize], giftBlockSize)
		giftXorTopBar(&input, &input, &offset)
		giftEncryptBlock(&y, key, input[:])
		c = c[giftBlockSize:]
		outPos += giftBlockSize
	}

	if len(ct) > 0 {
		giftTripleHalfBlock(&offset, &offset)
		if len(c)%giftBlockSize != 0 {
			giftTripleHalfBlock(&offset, &offset)
		}
		giftPhoPrime(&y, c, &input, out[outPos:outPos+len(c)], len(c))
		giftXorTopBar(&input, &input, &offset)
		giftEncryptBlock(&y, key, input[:])
	}

	if subtle.ConstantTimeCompare(tag, y[:giftCOFBTagSize]) != 1 {
		for i := range out {
			out[i] = 0
		}
		return nil, errors.New("giftcofb: authentication failed")
	}

	return out, nil
}

const giftBlockSize = 16

var giftRoundConstants = [40]byte{
	0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3E, 0x3D, 0x3B, 0x37, 0x2F,
	0x1E, 0x3C, 0x39, 0x33, 0x27, 0x0E, 0x1D, 0x3A, 0x35, 0x2B,
	0x16, 0x2C, 0x18, 0x30, 0x21, 0x02, 0x05, 0x0B, 0x17, 0x2E,
	0x1C, 0x38, 0x31, 0x23, 0x06, 0x0D, 0x1B, 0x36, 0x2D, 0x1A,
}

type giftBlock [giftBlockSize]byte
type giftHalfBlock [giftBlockSize / 2]byte

func giftcofbInitState(key, nonce, ad []byte, emptyM bool) (giftBlock, giftBlock, giftHalfBlock) {
	var input giftBlock
	copy(input[:], nonce[:giftBlockSize])

	var y giftBlock
	giftEncryptBlock(&y, key, input[:])

	var offset giftHalfBlock
	copy(offset[:], y[:len(offset)])

	a := ad
	alen := len(ad)

	for alen > giftBlockSize {
		giftPho1(&input, &y, a[:giftBlockSize], giftBlockSize)
		giftDoubleHalfBlock(&offset, &offset)
		giftXorTopBar(&input, &input, &offset)
		giftEncryptBlock(&y, key, input[:])
		a = a[giftBlockSize:]
		alen -= giftBlockSize
	}

	giftTripleHalfBlock(&offset, &offset)
	if alen%giftBlockSize != 0 || alen == 0 {
		giftTripleHalfBlock(&offset, &offset)
	}
	if emptyM {
		giftTripleHalfBlock(&offset, &offset)
		giftTripleHalfBlock(&offset, &offset)
	}

	var last []byte
	if alen > 0 {
		last = a[:alen]
	}
	giftPho1(&input, &y, last, alen)
	giftXorTopBar(&input, &input, &offset)
	giftEncryptBlock(&y, key, input[:])

	return y, input, offset
}

func giftEncryptBlock(out *giftBlock, key, in []byte) {
	var s [4]uint32
	for i := 0; i < 4; i++ {
		s[i] = binary.BigEndian.Uint32(in[i*4 : (i+1)*4])
	}

	var w [8]uint16
	for i := 0; i < 8; i++ {
		w[i] = binary.BigEndian.Uint16(key[i*2 : (i+1)*2])
	}

	for round := 0; round < 40; round++ {
		s[1] ^= s[0] & s[2]
		s[0] ^= s[1] & s[3]
		s[2] ^= s[0] | s[1]
		s[3] ^= s[2]
		s[1] ^= s[3]
		s[3] ^= 0xffffffff
		s[2] ^= s[0] & s[1]

		s[0], s[3] = s[3], s[0]

		s[0] = giftRowPerm(s[0], 0, 3, 2, 1)
		s[1] = giftRowPerm(s[1], 1, 0, 3, 2)
		s[2] = giftRowPerm(s[2], 2, 1, 0, 3)
		s[3] = giftRowPerm(s[3], 3, 2, 1, 0)

		s[2] ^= (uint32(w[2]) << 16) | uint32(w[3])
		s[1] ^= (uint32(w[6]) << 16) | uint32(w[7])
		s[3] ^= 0x80000000 ^ uint32(giftRoundConstants[round])

		t6 := (w[6] >> 2) | (w[6] << 14)
		t7 := (w[7] >> 12) | (w[7] << 4)
		w[7] = w[5]
		w[6] = w[4]
		w[5] = w[3]
		w[4] = w[2]
		w[3] = w[1]
		w[2] = w[0]
		w[1] = t7
		w[0] = t6
	}

	for i := 0; i < 4; i++ {
		binary.BigEndian.PutUint32(out[i*4:(i+1)*4], s[i])
	}
}

func giftRowPerm(s uint32, b0, b1, b2, b3 int) uint32 {
	var t uint32
	for b := 0; b < 8; b++ {
		t |= ((s >> (4*b + 0)) & 1) << uint(b+8*b0)
		t |= ((s >> (4*b + 1)) & 1) << uint(b+8*b1)
		t |= ((s >> (4*b + 2)) & 1) << uint(b+8*b2)
		t |= ((s >> (4*b + 3)) & 1) << uint(b+8*b3)
	}
	return t
}

func giftPho(y *giftBlock, m []byte, x *giftBlock, out []byte, n int) {
	for i := 0; i < n; i++ {
		out[i] = y[i] ^ m[i]
	}
	giftPho1(x, y, m, n)
}

func giftPhoPrime(y *giftBlock, c []byte, x *giftBlock, out []byte, n int) {
	for i := 0; i < n; i++ {
		out[i] = y[i] ^ c[i]
	}
	giftPho1(x, y, out[:n], n)
}

func giftPho1(dst *giftBlock, y *giftBlock, m []byte, n int) {
	giftG(y, y)
	var padded giftBlock
	giftPadding(&padded, m, n)
	for i := 0; i < giftBlockSize; i++ {
		dst[i] = y[i] ^ padded[i]
	}
}

func giftPadding(dst *giftBlock, src []byte, n int) {
	for i := range dst {
		dst[i] = 0
	}
	switch {
	case n == 0:
		dst[0] = 0x80
	case n < giftBlockSize:
		copy(dst[:n], src[:n])
		dst[n] = 0x80
	default:
		copy(dst[:], src[:giftBlockSize])
	}
}

func giftXorTopBar(dst *giftBlock, src *giftBlock, offset *giftHalfBlock) {
	for i := 0; i < len(offset); i++ {
		dst[i] = src[i] ^ offset[i]
	}
	for i := len(offset); i < giftBlockSize; i++ {
		dst[i] = src[i]
	}
}

func giftDoubleHalfBlock(dst *giftHalfBlock, src *giftHalfBlock) {
	var tmp giftHalfBlock
	for i := 0; i < len(tmp)-1; i++ {
		tmp[i] = (src[i] << 1) | (src[i+1] >> 7)
	}
	tmp[len(tmp)-1] = (src[len(tmp)-1] << 1) ^ ((src[0] >> 7) * 27)
	copy(dst[:], tmp[:])
}

func giftTripleHalfBlock(dst *giftHalfBlock, src *giftHalfBlock) {
	var doubled giftHalfBlock
	giftDoubleHalfBlock(&doubled, src)
	for i := range dst {
		dst[i] = src[i] ^ doubled[i]
	}
}

func giftG(dst *giftBlock, src *giftBlock) {
	var tmp giftBlock
	copy(tmp[:len(tmp)/2], src[len(tmp)/2:])
	for i := 0; i < len(tmp)/2-1; i++ {
		tmp[len(tmp)/2+i] = (src[i] << 1) | (src[i+1] >> 7)
	}
	tmp[len(tmp)-1] = (src[len(tmp)/2-1] << 1) | (src[0] >> 7)
	copy(dst[:], tmp[:])
}
