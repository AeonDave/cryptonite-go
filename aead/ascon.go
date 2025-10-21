package aead

import "errors"

// Implementation note: this mirrors the official Ascon reference code
// (SETBYTE/PAD helpers, little-endian byte layout). The literal constants
// therefore appear different from the spec's big-endian figures but map to the
// identical byte strings described in §2.3–§2.4 of the specification.

// ASCON-128 Authenticated Encryption implementation by AeonDave
// Based on the NIST Lightweight Cryptography standard winner (2023)
// NIST-recommended ASCON-128a variant
// Specification: https://ascon.iaik.tugraz.at/

const (
	asconKeySize   = 16 // 128 bits
	asconNonceSize = 16 // 128 bits
	asconTagSize   = 16 // 128 bits
	asconRate      = 16 // 128 bits per block (Ascon-128a)
)

// ASCON-128a initialization vector
var asconIV = uint64(0x00001000808c0001)

// asconState represents the 320-bit (5x64) ASCON permutation state
type asconState [5]uint64

// rotateRight performs right rotation of a 64-bit value
func rotateRight(x uint64, n uint) uint64 {
	return (x >> n) | (x << (64 - n))
}

// permute performs the ASCON permutation with 'rounds' rounds
func (s *asconState) permute(rounds int) {
	// Use the last 'rounds' constants (C6..C11 when rounds=6)
	for i := 12 - rounds; i < 12; i++ {
		// Addition of round constant
		s[2] ^= 0xf0 - uint64(i)*0x10 + uint64(i)

		// Substitution layer (5-bit S-box applied to each bit position)
		s[0] ^= s[4]
		s[4] ^= s[3]
		s[2] ^= s[1]

		t0 := s[0]
		t1 := s[1]
		t2 := s[2]
		t3 := s[3]
		t4 := s[4]

		s[0] = t0 ^ (^t1 & t2)
		s[1] = t1 ^ (^t2 & t3)
		s[2] = t2 ^ (^t3 & t4)
		s[3] = t3 ^ (^t4 & t0)
		s[4] = t4 ^ (^t0 & t1)

		s[1] ^= s[0]
		s[0] ^= s[4]
		s[3] ^= s[2]
		s[2] = ^s[2]

		// Linear diffusion layer
		s[0] ^= rotateRight(s[0], 19) ^ rotateRight(s[0], 28)
		s[1] ^= rotateRight(s[1], 61) ^ rotateRight(s[1], 39)
		s[2] ^= rotateRight(s[2], 1) ^ rotateRight(s[2], 6)
		s[3] ^= rotateRight(s[3], 10) ^ rotateRight(s[3], 17)
		s[4] ^= rotateRight(s[4], 7) ^ rotateRight(s[4], 41)
	}
}

// bytesToUint64 converts up to 8 bytes to uint64 (little-endian)
func bytesToUint64(b []byte) uint64 {
	var x uint64
	for i := range b {
		x |= uint64(b[i]) << (8 * i)
	}
	return x
}

// uint64ToBytes converts uint64 to 8 bytes (little-endian)
func uint64ToBytes(x uint64, b []byte) {
	for i := range b {
		b[i] = byte(x >> (8 * i))
	}
}

// pad returns a 64-bit value with the least significant 'length' bits set to 1
func pad(length int) uint64 {
	return uint64(1) << (8 * length)
}

// clearBytes clears the least significant 'n' bytes of 'x'
func clearBytes(x uint64, n int) uint64 {
	for i := 0; i < n; i++ {
		x &^= uint64(0xff) << (8 * i)
	}
	return x
}

// asconInitialize initializes the ASCON state with key and nonce
func asconInitialize(key, nonce []byte) asconState {
	var s asconState

	// Initialize state with IV, Key, and Nonce
	s[0] = asconIV
	s[1] = bytesToUint64(key[0:8])
	s[2] = bytesToUint64(key[8:16])
	s[3] = bytesToUint64(nonce[0:8])
	s[4] = bytesToUint64(nonce[8:16])

	// Initial permutation with 12 rounds (p^12)
	s.permute(12)

	// XOR key at the end
	s[3] ^= bytesToUint64(key[0:8])
	s[4] ^= bytesToUint64(key[8:16])

	return s
}

// asconFinalize generates the authentication tag
func asconFinalize(s *asconState, key []byte) []byte {
	K0 := bytesToUint64(key[0:8])
	K1 := bytesToUint64(key[8:16])

	s[2] ^= K0
	s[3] ^= K1
	s.permute(12)
	s[3] ^= K0
	s[4] ^= K1

	tag := make([]byte, asconTagSize)
	uint64ToBytes(s[3], tag[0:8])
	uint64ToBytes(s[4], tag[8:16])
	return tag
}

// processAssociatedData absorbs associated data into the state with correct padding
func processAssociatedData(s *asconState, ad []byte) {
	if len(ad) > 0 {
		offset := 0
		for offset+asconRate <= len(ad) {
			s[0] ^= bytesToUint64(ad[offset : offset+8])
			s[1] ^= bytesToUint64(ad[offset+8 : offset+16])
			s.permute(8)
			offset += asconRate
		}

		remaining := len(ad) - offset
		if remaining >= 8 {
			s[0] ^= bytesToUint64(ad[offset : offset+8])
			rest := remaining - 8
			if rest > 0 {
				s[1] ^= bytesToUint64(ad[offset+8 : offset+8+rest])
			}
			s[1] ^= pad(rest)
		} else {
			s[0] ^= bytesToUint64(ad[offset : offset+remaining])
			s[0] ^= pad(remaining)
		}
		s.permute(8)
	}

	s[4] ^= 0x8000000000000000
}

// ascon128 implements the Aead interface for the ASCON-128 algorithm.
type ascon128 struct{}

// NewAscon128 returns a zero-allocation AEAD cipher instance.
func NewAscon128() Aead {
	return ascon128{}
}

func (ascon128) Encrypt(key, nonce, ad, plaintext []byte) ([]byte, error) {
	if len(key) != asconKeySize {
		return nil, errors.New("ascon: invalid key size")
	}
	if len(nonce) != asconNonceSize {
		return nil, errors.New("ascon: invalid nonce size")
	}

	s := asconInitialize(key, nonce)
	processAssociatedData(&s, ad)

	ciphertext := make([]byte, len(plaintext))
	offset := 0

	for offset+asconRate <= len(plaintext) {
		m0 := bytesToUint64(plaintext[offset : offset+8])
		m1 := bytesToUint64(plaintext[offset+8 : offset+16])
		s[0] ^= m0
		s[1] ^= m1
		uint64ToBytes(s[0], ciphertext[offset:offset+8])
		uint64ToBytes(s[1], ciphertext[offset+8:offset+16])
		s.permute(8)
		offset += asconRate
	}

	remaining := len(plaintext) - offset
	if remaining > 0 {
		if remaining >= 8 {
			s[0] ^= bytesToUint64(plaintext[offset : offset+8])
			uint64ToBytes(s[0], ciphertext[offset:offset+8])

			rest := remaining - 8
			if rest > 0 {
				s[1] ^= bytesToUint64(plaintext[offset+8 : offset+8+rest])
				var tmp [8]byte
				uint64ToBytes(s[1], tmp[:])
				copy(ciphertext[offset+8:], tmp[:rest])
			}
			s[1] ^= pad(rest)
		} else {
			s[0] ^= bytesToUint64(plaintext[offset : offset+remaining])
			var tmp [8]byte
			uint64ToBytes(s[0], tmp[:])
			copy(ciphertext[offset:], tmp[:remaining])
			s[0] ^= pad(remaining)
		}
	} else {
		s[0] ^= 0x01
	}

	tag := asconFinalize(&s, key)

	result := make([]byte, len(ciphertext)+asconTagSize)
	copy(result, ciphertext)
	copy(result[len(ciphertext):], tag)
	for i := range tag {
		tag[i] = 0
	}
	s = asconState{}
	return result, nil
}

func (ascon128) Decrypt(key, nonce, ad, ciphertextAndTag []byte) ([]byte, error) {
	if len(key) != asconKeySize {
		return nil, errors.New("ascon: invalid key size")
	}
	if len(nonce) != asconNonceSize {
		return nil, errors.New("ascon: invalid nonce size")
	}
	if len(ciphertextAndTag) < asconTagSize {
		return nil, errors.New("ascon: ciphertext too short")
	}

	ciphertextLen := len(ciphertextAndTag) - asconTagSize
	ciphertext := ciphertextAndTag[:ciphertextLen]
	receivedTag := ciphertextAndTag[ciphertextLen:]

	s := asconInitialize(key, nonce)
	processAssociatedData(&s, ad)

	plaintext := make([]byte, len(ciphertext))
	offset := 0

	for offset+asconRate <= len(ciphertext) {
		c0 := bytesToUint64(ciphertext[offset : offset+8])
		c1 := bytesToUint64(ciphertext[offset+8 : offset+16])
		p0 := s[0] ^ c0
		p1 := s[1] ^ c1
		uint64ToBytes(p0, plaintext[offset:offset+8])
		uint64ToBytes(p1, plaintext[offset+8:offset+16])
		s[0] = c0
		s[1] = c1
		s.permute(8)
		offset += asconRate
	}

	remaining := len(ciphertext) - offset
	if remaining > 0 {
		if remaining >= 8 {
			c0 := bytesToUint64(ciphertext[offset : offset+8])
			rest := remaining - 8
			var tmp [8]byte
			uint64ToBytes(s[0]^c0, tmp[:])
			copy(plaintext[offset:], tmp[:8])

			var c1 uint64
			if rest > 0 {
				c1 = bytesToUint64(ciphertext[offset+8 : offset+8+rest])
				uint64ToBytes(s[1]^c1, tmp[:])
				copy(plaintext[offset+8:], tmp[:rest])
			}

			s[0] = c0
			s[1] = clearBytes(s[1], rest)
			s[1] |= c1
			s[1] ^= pad(rest)
		} else {
			c0 := bytesToUint64(ciphertext[offset : offset+remaining])
			var tmp [8]byte
			uint64ToBytes(s[0]^c0, tmp[:])
			copy(plaintext[offset:], tmp[:remaining])
			s[0] = clearBytes(s[0], remaining)
			s[0] |= c0
			s[0] ^= pad(remaining)
		}
	} else {
		s[0] ^= 0x01
	}

	expectedTag := asconFinalize(&s, key)
	var diff byte
	for i := 0; i < asconTagSize; i++ {
		diff |= receivedTag[i] ^ expectedTag[i]
	}
	for i := range expectedTag {
		expectedTag[i] = 0
	}
	if diff != 0 {
		for i := range plaintext {
			plaintext[i] = 0
		}
		s = asconState{}
		return nil, errors.New("ascon: authentication failed")
	}

	s = asconState{}
	return plaintext, nil
}
