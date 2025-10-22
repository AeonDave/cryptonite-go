package aead

import "errors"

const (
	ascon80pqKeySize   = 20
	ascon80pqNonceSize = 16
	ascon80pqTagSize   = 16
	ascon80pqRate      = 8
)

var ascon80pqIV = [4]byte{0xa0, 0x40, 0x0c, 0x06}

func bytesToUint64BE(b []byte) uint64 {
	var x uint64
	for i := 0; i < len(b); i++ {
		x = (x << 8) | uint64(b[i])
	}
	return x
}

func uint64ToBytesBE(x uint64, out []byte) {
	for i := len(out) - 1; i >= 0; i-- {
		out[i] = byte(x)
		x >>= 8
	}
}

func ascon80pqInitialize(key, nonce []byte) asconState {
	var stateBytes [40]byte
	copy(stateBytes[:4], ascon80pqIV[:])
	copy(stateBytes[4:24], key)
	copy(stateBytes[24:], nonce)

	var s asconState
	for i := 0; i < 5; i++ {
		s[i] = bytesToUint64BE(stateBytes[i*8 : (i+1)*8])
	}

	s.permute(12)

	var keyStateBytes [40]byte
	copy(keyStateBytes[40-len(key):], key)
	for i := 0; i < 5; i++ {
		s[i] ^= bytesToUint64BE(keyStateBytes[i*8 : (i+1)*8])
	}

	return s
}

func ascon80pqProcessAssociatedData(s *asconState, ad []byte) {
	if len(ad) > 0 {
		offset := 0
		for offset+ascon80pqRate <= len(ad) {
			(*s)[0] ^= bytesToUint64BE(ad[offset : offset+ascon80pqRate])
			s.permute(6)
			offset += ascon80pqRate
		}

		var block [ascon80pqRate]byte
		remaining := len(ad) - offset
		copy(block[:], ad[offset:])
		block[remaining] = 0x80
		(*s)[0] ^= bytesToUint64BE(block[:])
		s.permute(6)
		for i := range block {
			block[i] = 0
		}
	}
	(*s)[4] ^= 1
}

func ascon80pqFinalize(s *asconState, key []byte) []byte {
	(*s)[1] ^= bytesToUint64BE(key[0:8])
	(*s)[2] ^= bytesToUint64BE(key[8:16])
	var block [8]byte
	copy(block[:4], key[16:])
	(*s)[3] ^= bytesToUint64BE(block[:])
	s.permute(12)
	copy(block[:], key[len(key)-16:len(key)-8])
	(*s)[3] ^= bytesToUint64BE(block[:])
	copy(block[:], key[len(key)-8:])
	(*s)[4] ^= bytesToUint64BE(block[:])
	tag := make([]byte, ascon80pqTagSize)
	uint64ToBytesBE((*s)[3], tag[:8])
	uint64ToBytesBE((*s)[4], tag[8:])
	for i := range block {
		block[i] = 0
	}
	return tag
}

type ascon80pq struct{}

func NewAscon80pq() Aead {
	return ascon80pq{}
}

func (ascon80pq) Encrypt(key, nonce, ad, plaintext []byte) ([]byte, error) {
	if len(key) != ascon80pqKeySize {
		return nil, errors.New("ascon80pq: invalid key size")
	}
	if len(nonce) != ascon80pqNonceSize {
		return nil, errors.New("ascon80pq: invalid nonce size")
	}

	s := ascon80pqInitialize(key, nonce)
	ascon80pqProcessAssociatedData(&s, ad)

	ciphertext := make([]byte, len(plaintext))
	offset := 0
	for offset+ascon80pqRate <= len(plaintext) {
		block := bytesToUint64BE(plaintext[offset : offset+ascon80pqRate])
		s[0] ^= block
		uint64ToBytesBE(s[0], ciphertext[offset:offset+ascon80pqRate])
		s.permute(6)
		offset += ascon80pqRate
	}

	var blockBytes [ascon80pqRate]byte
	remaining := len(plaintext) - offset
	copy(blockBytes[:], plaintext[offset:])
	blockBytes[remaining] = 0x80
	block := bytesToUint64BE(blockBytes[:])
	s[0] ^= block
	if remaining > 0 {
		var tmp [ascon80pqRate]byte
		uint64ToBytesBE(s[0], tmp[:])
		copy(ciphertext[offset:], tmp[:remaining])
		for i := range tmp {
			tmp[i] = 0
		}
	}
	for i := range blockBytes {
		blockBytes[i] = 0
	}

	tag := ascon80pqFinalize(&s, key)
	result := make([]byte, len(ciphertext)+ascon80pqTagSize)
	copy(result, ciphertext)
	copy(result[len(ciphertext):], tag)
	for i := range tag {
		tag[i] = 0
	}
	s = asconState{}
	return result, nil
}

func (ascon80pq) Decrypt(key, nonce, ad, ciphertextAndTag []byte) ([]byte, error) {
	if len(key) != ascon80pqKeySize {
		return nil, errors.New("ascon80pq: invalid key size")
	}
	if len(nonce) != ascon80pqNonceSize {
		return nil, errors.New("ascon80pq: invalid nonce size")
	}
	if len(ciphertextAndTag) < ascon80pqTagSize {
		return nil, errors.New("ascon80pq: ciphertext too short")
	}

	ciphertextLen := len(ciphertextAndTag) - ascon80pqTagSize
	ciphertext := ciphertextAndTag[:ciphertextLen]
	receivedTag := ciphertextAndTag[ciphertextLen:]

	s := ascon80pqInitialize(key, nonce)
	ascon80pqProcessAssociatedData(&s, ad)

	plaintext := make([]byte, len(ciphertext))
	offset := 0
	for offset+ascon80pqRate <= len(ciphertext) {
		Ci := bytesToUint64BE(ciphertext[offset : offset+ascon80pqRate])
		Pi := s[0] ^ Ci
		uint64ToBytesBE(Pi, plaintext[offset:offset+ascon80pqRate])
		s[0] = Ci
		s.permute(6)
		offset += ascon80pqRate
	}

	var blockBytes [ascon80pqRate]byte
	remaining := len(ciphertext) - offset
	copy(blockBytes[:], ciphertext[offset:])
	Ci := bytesToUint64BE(blockBytes[:])
	if remaining > 0 {
		var tmp [ascon80pqRate]byte
		uint64ToBytesBE(s[0]^Ci, tmp[:])
		copy(plaintext[offset:], tmp[:remaining])
		for i := range tmp {
			tmp[i] = 0
		}
	}
	mask := ^uint64(0) >> (remaining * 8)
	padding := uint64(0x80) << ((ascon80pqRate - remaining - 1) * 8)
	s[0] = Ci ^ (s[0] & mask) ^ padding
	for i := range blockBytes {
		blockBytes[i] = 0
	}

	expectedTag := ascon80pqFinalize(&s, key)
	var diff byte
	for i := 0; i < ascon80pqTagSize; i++ {
		diff |= expectedTag[i] ^ receivedTag[i]
	}
	for i := range expectedTag {
		expectedTag[i] = 0
	}
	if diff != 0 {
		for i := range plaintext {
			plaintext[i] = 0
		}
		s = asconState{}
		return nil, errors.New("ascon80pq: authentication failed")
	}

	s = asconState{}
	return plaintext, nil
}
