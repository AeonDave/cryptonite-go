package chacha20

import "encoding/binary"

const (
	BlockSize = 64
	Rounds    = 20
	KeySize   = 32
	NonceSize = 12
)

var constants = [4]uint32{
	0x61707865, // "expa"
	0x3320646e, // "nd 3"
	0x79622d32, // "2-by"
	0x6b206574, // "te k"
}

func quarterRound(state *[16]uint32, a, b, c, d int) {
	state[a] += state[b]
	state[d] ^= state[a]
	state[d] = (state[d] << 16) | (state[d] >> 16)

	state[c] += state[d]
	state[b] ^= state[c]
	state[b] = (state[b] << 12) | (state[b] >> 20)

	state[a] += state[b]
	state[d] ^= state[a]
	state[d] = (state[d] << 8) | (state[d] >> 24)

	state[c] += state[d]
	state[b] ^= state[c]
	state[b] = (state[b] << 7) | (state[b] >> 25)
}

func block(key []byte, counter uint32, nonce []byte, out *[BlockSize]byte) {
	var state [16]uint32

	state[0] = constants[0]
	state[1] = constants[1]
	state[2] = constants[2]
	state[3] = constants[3]

	for i := range 8 {
		state[4+i] = binary.LittleEndian.Uint32(key[i*4:])
	}

	state[12] = counter
	state[13] = binary.LittleEndian.Uint32(nonce[0:4])
	state[14] = binary.LittleEndian.Uint32(nonce[4:8])
	state[15] = binary.LittleEndian.Uint32(nonce[8:12])

	working := state
	for round := 0; round < Rounds; round += 2 {
		quarterRound(&working, 0, 4, 8, 12)
		quarterRound(&working, 1, 5, 9, 13)
		quarterRound(&working, 2, 6, 10, 14)
		quarterRound(&working, 3, 7, 11, 15)
		quarterRound(&working, 0, 5, 10, 15)
		quarterRound(&working, 1, 6, 11, 12)
		quarterRound(&working, 2, 7, 8, 13)
		quarterRound(&working, 3, 4, 9, 14)
	}

	for i := range 16 {
		working[i] += state[i]
		binary.LittleEndian.PutUint32(out[i*4:], working[i])
	}
}

// XORKeyStream XORs src with the ChaCha20 keystream and writes the result to dst.
func XORKeyStream(dst, src, key, nonce []byte, counter uint32) {
	if len(key) != KeySize {
		panic("chacha20: invalid key size")
	}
	if len(nonce) != NonceSize {
		panic("chacha20: invalid nonce size")
	}
	if len(dst) < len(src) {
		panic("chacha20: destination too short")
	}

	var blk [BlockSize]byte
	for len(src) > 0 {
		block(key, counter, nonce, &blk)
		counter++

		n := min(len(src), BlockSize)
		for i := range n {
			dst[i] = src[i] ^ blk[i]
		}
		dst = dst[n:]
		src = src[n:]
	}
}

// DerivePoly1305Key derives the Poly1305 key for ChaCha20-Poly1305.
func DerivePoly1305Key(out *[32]byte, key, nonce []byte) {
	if len(key) != KeySize {
		panic("chacha20: invalid key size")
	}
	if len(nonce) != NonceSize {
		panic("chacha20: invalid nonce size")
	}
	var blk [BlockSize]byte
	block(key, 0, nonce, &blk)
	copy(out[:], blk[:32])
}

// HChaCha20 derives a subkey from key and 16-byte nonce, as defined in RFC 8439.
func HChaCha20(out *[32]byte, key, nonce []byte) {
	if len(key) != KeySize {
		panic("chacha20: invalid key size")
	}
	if len(nonce) != 16 {
		panic("chacha20: invalid nonce size for HChaCha20")
	}

	var state [16]uint32
	state[0] = constants[0]
	state[1] = constants[1]
	state[2] = constants[2]
	state[3] = constants[3]
	for i := range 8 {
		state[4+i] = binary.LittleEndian.Uint32(key[i*4:])
	}
	state[12] = binary.LittleEndian.Uint32(nonce[0:4])
	state[13] = binary.LittleEndian.Uint32(nonce[4:8])
	state[14] = binary.LittleEndian.Uint32(nonce[8:12])
	state[15] = binary.LittleEndian.Uint32(nonce[12:16])

	working := state
	for round := 0; round < Rounds; round += 2 {
		quarterRound(&working, 0, 4, 8, 12)
		quarterRound(&working, 1, 5, 9, 13)
		quarterRound(&working, 2, 6, 10, 14)
		quarterRound(&working, 3, 7, 11, 15)
		quarterRound(&working, 0, 5, 10, 15)
		quarterRound(&working, 1, 6, 11, 12)
		quarterRound(&working, 2, 7, 8, 13)
		quarterRound(&working, 3, 4, 9, 14)
	}

	binary.LittleEndian.PutUint32(out[0:4], working[0])
	binary.LittleEndian.PutUint32(out[4:8], working[1])
	binary.LittleEndian.PutUint32(out[8:12], working[2])
	binary.LittleEndian.PutUint32(out[12:16], working[3])
	binary.LittleEndian.PutUint32(out[16:20], working[12])
	binary.LittleEndian.PutUint32(out[20:24], working[13])
	binary.LittleEndian.PutUint32(out[24:28], working[14])
	binary.LittleEndian.PutUint32(out[28:32], working[15])
}
