package aead

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

const (
	aesGCMSIVTagSize   = 16
	aesGCMSIVNonceSize = 12
)

type aesGCMSIV struct{}

// NewAesGcmSiv returns an AEAD instance implementing AES-GCM-SIV as defined in RFC 8452.
// Keys must be 16 or 32 bytes long, and nonces must always be 12 bytes.
func NewAesGcmSiv() Aead { return aesGCMSIV{} }

func (aesGCMSIV) Encrypt(key, nonce, ad, plaintext []byte) ([]byte, error) {
	if len(key) != 16 && len(key) != 32 {
		return nil, errors.New("aesgcmsiv: invalid key size")
	}
	if len(nonce) != aesGCMSIVNonceSize {
		return nil, errors.New("aesgcmsiv: invalid nonce size")
	}
	authKey, encKey, err := deriveGCMSIVKeys(key, nonce)
	if err != nil {
		return nil, err
	}
	hash := polyvalDigest(authKey, ad, plaintext)
	for i := 0; i < aesGCMSIVNonceSize; i++ {
		hash[i] ^= nonce[i]
	}
	hash[aesGCMSIVTagSize-1] &= 0x7f
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	var tag [aesGCMSIVTagSize]byte
	block.Encrypt(tag[:], hash[:])
	ciphertext := make([]byte, len(plaintext)+aesGCMSIVTagSize)
	streamXORCipher(block, tag, plaintext, ciphertext[:len(plaintext)])
	copy(ciphertext[len(plaintext):], tag[:])
	return ciphertext, nil
}

func (aesGCMSIV) Decrypt(key, nonce, ad, ciphertextAndTag []byte) ([]byte, error) {
	if len(key) != 16 && len(key) != 32 {
		return nil, errors.New("aesgcmsiv: invalid key size")
	}
	if len(nonce) != aesGCMSIVNonceSize {
		return nil, errors.New("aesgcmsiv: invalid nonce size")
	}
	if len(ciphertextAndTag) < aesGCMSIVTagSize {
		return nil, errors.New("aesgcmsiv: ciphertext too short")
	}
	authKey, encKey, err := deriveGCMSIVKeys(key, nonce)
	if err != nil {
		return nil, err
	}
	tagPos := len(ciphertextAndTag) - aesGCMSIVTagSize
	ciphertext := ciphertextAndTag[:tagPos]
	tag := ciphertextAndTag[tagPos:]
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, len(ciphertext))
	streamXORCipher(block, bytesToArray16(tag), ciphertext, plaintext)
	hash := polyvalDigest(authKey, ad, plaintext)
	for i := 0; i < aesGCMSIVNonceSize; i++ {
		hash[i] ^= nonce[i]
	}
	hash[aesGCMSIVTagSize-1] &= 0x7f
	expected := make([]byte, aesGCMSIVTagSize)
	block.Encrypt(expected, hash[:])
	if subtle.ConstantTimeCompare(expected, tag) != 1 {
		return nil, errors.New("aesgcmsiv: authentication failed")
	}
	return plaintext, nil
}

func deriveGCMSIVKeys(masterKey, nonce []byte) ([aesGCMSIVTagSize]byte, []byte, error) {
	var authKey [aesGCMSIVTagSize]byte
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return authKey, nil, err
	}
	var counterBlock [aesGCMSIVTagSize]byte
	copy(counterBlock[4:], nonce)
	var encrypted [aesGCMSIVTagSize]byte
	writeHalf := func(idx uint32, dst []byte) {
		binary.LittleEndian.PutUint32(counterBlock[:4], idx)
		block.Encrypt(encrypted[:], counterBlock[:])
		copy(dst, encrypted[:8])
	}
	writeHalf(0, authKey[0:8])
	writeHalf(1, authKey[8:16])
	encKey := make([]byte, len(masterKey))
	for i := 0; i < len(encKey); i += 8 {
		writeHalf(uint32(2+i/8), encKey[i:i+8])
	}
	return authKey, encKey, nil
}

func polyvalDigest(authKey [aesGCMSIVTagSize]byte, ad, plaintext []byte) [aesGCMSIVTagSize]byte {
	state := newPolyval(authKey)
	state.update(ad)
	state.update(plaintext)
	var lengthBlock [aesGCMSIVTagSize]byte
	binary.LittleEndian.PutUint64(lengthBlock[:8], uint64(len(ad))*8)
	binary.LittleEndian.PutUint64(lengthBlock[8:], uint64(len(plaintext))*8)
	state.update(lengthBlock[:])
	return state.finish()
}

func streamXORCipher(block cipher.Block, tag [aesGCMSIVTagSize]byte, src []byte, dst []byte) {
	var counter [aesGCMSIVTagSize]byte
	copy(counter[:], tag[:])
	counter[aesGCMSIVTagSize-1] |= 0x80
	ctr := binary.LittleEndian.Uint32(counter[:4])
	var keystream [aesGCMSIVTagSize]byte
	offset := 0
	for offset < len(src) {
		block.Encrypt(keystream[:], counter[:])
		ctr++
		binary.LittleEndian.PutUint32(counter[:4], ctr)
		n := xorInto(dst[offset:], src[offset:], keystream[:])
		offset += n
	}
}

func xorInto(dst, a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b[i]
	}
	return n
}

func bytesToArray16(in []byte) [aesGCMSIVTagSize]byte {
	var out [aesGCMSIVTagSize]byte
	copy(out[:], in)
	return out
}

type polyvalState struct {
	key gf128
	acc gf128
}

func newPolyval(keyBytes [aesGCMSIVTagSize]byte) *polyvalState {
	return &polyvalState{
		key: gf128{
			lo: binary.LittleEndian.Uint64(keyBytes[:8]),
			hi: binary.LittleEndian.Uint64(keyBytes[8:]),
		},
	}
}

func (p *polyvalState) update(data []byte) {
	for len(data) >= aesGCMSIVTagSize {
		p.mixBlock(data[:aesGCMSIVTagSize])
		data = data[aesGCMSIVTagSize:]
	}
	if len(data) > 0 {
		var block [aesGCMSIVTagSize]byte
		copy(block[:], data)
		p.mixBlock(block[:])
	}
}

func (p *polyvalState) mixBlock(block []byte) {
	p.acc.lo ^= binary.LittleEndian.Uint64(block[:8])
	p.acc.hi ^= binary.LittleEndian.Uint64(block[8:])
	p.acc = polyvalMul(p.acc, p.key)
}

func (p *polyvalState) finish() [aesGCMSIVTagSize]byte {
	var out [aesGCMSIVTagSize]byte
	binary.LittleEndian.PutUint64(out[:8], p.acc.lo)
	binary.LittleEndian.PutUint64(out[8:], p.acc.hi)
	return out
}

type gf128 struct {
	lo uint64
	hi uint64
}

func polyvalMul(a, b gf128) gf128 {
	loProd := clMul64(a.lo, b.lo)
	hiProd := clMul64(a.hi, b.hi)
	mid := clMul64(a.lo^a.hi, b.lo^b.hi)
	mid.lo ^= loProd.lo ^ hiProd.lo
	mid.hi ^= loProd.hi ^ hiProd.hi
	hiProd.lo ^= mid.hi
	loProd.hi ^= mid.lo
	loProd.hi ^= (loProd.lo << 63) ^ (loProd.lo << 62) ^ (loProd.lo << 57)
	hiProd.lo ^= loProd.lo
	hiProd.hi ^= loProd.hi
	hiProd.lo ^= loProd.lo >> 1
	hiProd.lo ^= loProd.hi << 63
	hiProd.hi ^= loProd.hi >> 1
	hiProd.lo ^= loProd.lo >> 2
	hiProd.lo ^= loProd.hi << 62
	hiProd.hi ^= loProd.hi >> 2
	hiProd.lo ^= loProd.lo >> 7
	hiProd.lo ^= loProd.hi << 57
	hiProd.hi ^= loProd.hi >> 7
	return hiProd
}

func clMul64(x, y uint64) gf128 {
	x0 := uint32(x)
	x1 := uint32(x >> 32)
	y0 := uint32(y)
	y1 := uint32(y >> 32)
	p0 := clMul32(x0, y0)
	p1 := clMul32(x1, y1)
	pMid := clMul32(x0^x1, y0^y1) ^ p0 ^ p1
	return gf128{
		lo: p0 ^ (pMid << 32),
		hi: p1 ^ (pMid >> 32),
	}
}

func clMul32(x, y uint32) uint64 {
	var result uint64
	var base uint64 = uint64(x)
	for shift := 0; shift < 32; shift += 4 {
		nib := (uint64(y) >> shift) & 0xF
		if nib == 0 {
			continue
		}
		var partial uint64
		if nib&0x1 != 0 {
			partial ^= base
		}
		if nib&0x2 != 0 {
			partial ^= base << 1
		}
		if nib&0x4 != 0 {
			partial ^= base << 2
		}
		if nib&0x8 != 0 {
			partial ^= base << 3
		}
		result ^= partial << shift
	}
	return result
}
