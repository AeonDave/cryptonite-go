package aead

import (
	"crypto/subtle"
	"errors"
)

const (
	skinnyKeySize   = 16
	skinnyNonceSize = 16
	skinnyTagSize   = 16
	skinnyBlockSize = 16
	skinnyRounds    = 56
)

type skinnyAead struct{}

// NewSkinnyAead returns an AEAD implementation of SKINNY-AEAD-M1.
func NewSkinnyAead() Aead {
	return skinnyAead{}
}

func (skinnyAead) Encrypt(key, nonce, ad, plaintext []byte) ([]byte, error) {
	if len(key) != skinnyKeySize {
		return nil, errors.New("skinnyaead: invalid key size")
	}
	if len(nonce) != skinnyNonceSize {
		return nil, errors.New("skinnyaead: invalid nonce size")
	}

	out := make([]byte, len(plaintext)+skinnyTagSize)
	ciphertext := out[:len(plaintext)]
	tag := out[len(plaintext):]

	var tweakey skinnyTweakeyState
	tweakey.setKey(key)
	tweakey.setNonce(nonce)

	var auth, lastBlock, checksum, final, zeroBlock, pad, temp skinnyBlock

	if len(ad) > 0 {
		tweakey.setStage(stageADFull)
		counter := uint64(1)
		processed := 0
		for remaining := len(ad); remaining >= skinnyBlockSize; remaining -= skinnyBlockSize {
			tweakey.setBlockNumber(counter)
			skinnyEncryptBlock(&temp, ad[processed:processed+skinnyBlockSize], &tweakey)
			auth.xor(&temp)
			processed += skinnyBlockSize
			counter = skinnyLFSR(counter)
		}

		if processed < len(ad) {
			lastBlock.clear()
			copy(lastBlock[:], ad[processed:])
			lastBlock[len(ad)-processed] = 0x80
			tweakey.setStage(stageADPartial)
			tweakey.setBlockNumber(counter)
			skinnyEncryptBlock(&temp, lastBlock[:], &tweakey)
			auth.xor(&temp)
		}
	}

	checksum.clear()
	tweakey.setStage(stageEncFull)
	counter := uint64(1)
	processed := 0
	for remaining := len(plaintext); remaining >= skinnyBlockSize; remaining -= skinnyBlockSize {
		block := plaintext[processed : processed+skinnyBlockSize]
		checksum.xorBytes(block)
		tweakey.setBlockNumber(counter)
		skinnyEncryptBlock(&temp, block, &tweakey)
		copy(ciphertext[processed:processed+skinnyBlockSize], temp[:])
		processed += skinnyBlockSize
		counter = skinnyLFSR(counter)
	}

	if processed < len(plaintext) {
		partial := plaintext[processed:]
		lastBlock.clear()
		copy(lastBlock[:], partial)
		lastBlock[len(partial)] = 0x80
		checksum.xor(&lastBlock)

		zeroBlock.clear()
		tweakey.setStage(stageEncPartial)
		tweakey.setBlockNumber(counter)
		skinnyEncryptBlock(&pad, zeroBlock[:], &tweakey)
		for i := range partial {
			ciphertext[processed+i] = lastBlock[i] ^ pad[i]
		}

		tweakey.setStage(stageTagPartial)
		counter = skinnyLFSR(counter)
		tweakey.setBlockNumber(counter)
		skinnyEncryptBlock(&final, checksum[:], &tweakey)
	} else {
		tweakey.setStage(stageTagFull)
		tweakey.setBlockNumber(counter)
		skinnyEncryptBlock(&final, checksum[:], &tweakey)
	}

	for i := 0; i < skinnyTagSize; i++ {
		tag[i] = final[i] ^ auth[i]
	}

	return out, nil
}

func (skinnyAead) Decrypt(key, nonce, ad, ciphertextAndTag []byte) ([]byte, error) {
	if len(key) != skinnyKeySize {
		return nil, errors.New("skinnyaead: invalid key size")
	}
	if len(nonce) != skinnyNonceSize {
		return nil, errors.New("skinnyaead: invalid nonce size")
	}
	if len(ciphertextAndTag) < skinnyTagSize {
		return nil, errors.New("skinnyaead: ciphertext too short")
	}

	ct := ciphertextAndTag[:len(ciphertextAndTag)-skinnyTagSize]
	tag := ciphertextAndTag[len(ciphertextAndTag)-skinnyTagSize:]

	out := make([]byte, len(ct))

	var tweakey skinnyTweakeyState
	tweakey.setKey(key)
	tweakey.setNonce(nonce)

	var auth, lastBlock, checksum, final, zeroBlock, pad, temp skinnyBlock

	if len(ad) > 0 {
		tweakey.setStage(stageADFull)
		counter := uint64(1)
		processed := 0
		for remaining := len(ad); remaining >= skinnyBlockSize; remaining -= skinnyBlockSize {
			tweakey.setBlockNumber(counter)
			skinnyEncryptBlock(&temp, ad[processed:processed+skinnyBlockSize], &tweakey)
			auth.xor(&temp)
			processed += skinnyBlockSize
			counter = skinnyLFSR(counter)
		}
		if processed < len(ad) {
			lastBlock.clear()
			copy(lastBlock[:], ad[processed:])
			lastBlock[len(ad)-processed] = 0x80
			tweakey.setStage(stageADPartial)
			tweakey.setBlockNumber(counter)
			skinnyEncryptBlock(&temp, lastBlock[:], &tweakey)
			auth.xor(&temp)
		}
	}

	checksum.clear()
	tweakey.setStage(stageEncFull)
	counter := uint64(1)
	processed := 0
	for remaining := len(ct); remaining >= skinnyBlockSize; remaining -= skinnyBlockSize {
		block := ct[processed : processed+skinnyBlockSize]
		tweakey.setBlockNumber(counter)
		skinnyDecryptBlock(&temp, block, &tweakey)
		copy(out[processed:processed+skinnyBlockSize], temp[:])
		checksum.xor(&temp)
		processed += skinnyBlockSize
		counter = skinnyLFSR(counter)
	}

	if processed == len(ct) {
		tweakey.setStage(stageTagFull)
		tweakey.setBlockNumber(counter)
		skinnyEncryptBlock(&final, checksum[:], &tweakey)
		final.xor(&auth)
		if subtle.ConstantTimeCompare(final[:], tag) != 1 {
			for i := range out {
				out[i] = 0
			}
			return nil, errors.New("skinnyaead: authentication failed")
		}
		return out, nil
	}

	partial := ct[processed:]
	zeroBlock.clear()
	tweakey.setStage(stageEncPartial)
	tweakey.setBlockNumber(counter)
	skinnyEncryptBlock(&pad, zeroBlock[:], &tweakey)
	lastBlock.clear()
	copy(lastBlock[:], partial)
	for i := range partial {
		lastBlock[i] ^= pad[i]
		out[processed+i] = lastBlock[i]
	}
	lastBlock[len(partial)] = 0x80
	checksum.xor(&lastBlock)

	tweakey.setStage(stageTagPartial)
	counter = skinnyLFSR(counter)
	tweakey.setBlockNumber(counter)
	skinnyEncryptBlock(&final, checksum[:], &tweakey)
	final.xor(&auth)
	if subtle.ConstantTimeCompare(final[:], tag) != 1 {
		for i := range out {
			out[i] = 0
		}
		return nil, errors.New("skinnyaead: authentication failed")
	}

	return out, nil
}

type skinnyBlock [skinnyBlockSize]byte

type skinnyTweakeyState [48]byte

const (
	stageEncFull    = 0x0
	stageEncPartial = 0x1
	stageADFull     = 0x2
	stageADPartial  = 0x3
	stageTagFull    = 0x4
	stageTagPartial = 0x5
)

func (tk *skinnyTweakeyState) setKey(key []byte) {
	copy(tk[32:], key)
}

func (tk *skinnyTweakeyState) setNonce(nonce []byte) {
	copy(tk[16:], nonce)
}

func (tk *skinnyTweakeyState) setStage(stage byte) {
	tk[15] = stage
}

func (tk *skinnyTweakeyState) setBlockNumber(counter uint64) {
	for i := 0; i < 8; i++ {
		tk[i] = byte(counter >> (8 * i))
	}
}

func skinnyLFSR(counter uint64) uint64 {
	feedback := (counter >> 63) & 1
	counter <<= 1
	if feedback == 1 {
		counter ^= 0x1B
	}
	return counter
}

func skinnyEncryptBlock(out *skinnyBlock, in []byte, tk *skinnyTweakeyState) {
	var state [4][4]byte
	var keyCells [3][4][4]byte

	for i := 0; i < skinnyBlockSize; i++ {
		state[i>>2][i&3] = in[i]
		keyCells[0][i>>2][i&3] = tk[i]
		keyCells[1][i>>2][i&3] = tk[i+16]
		keyCells[2][i>>2][i&3] = tk[i+32]
	}

	for round := 0; round < skinnyRounds; round++ {
		skinnySubCells(&state)
		skinnyAddConstants(&state, round)
		skinnyAddKey(&state, &keyCells)
		skinnyShiftRows(&state)
		skinnyMixColumns(&state)
	}

	for i := 0; i < skinnyBlockSize; i++ {
		out[i] = state[i>>2][i&3]
	}
}

func skinnyDecryptBlock(out *skinnyBlock, in []byte, tk *skinnyTweakeyState) {
	var state [4][4]byte
	var keyCells [3][4][4]byte
	var dummy [4][4]byte

	for i := 0; i < skinnyBlockSize; i++ {
		state[i>>2][i&3] = in[i]
		keyCells[0][i>>2][i&3] = tk[i]
		keyCells[1][i>>2][i&3] = tk[i+16]
		keyCells[2][i>>2][i&3] = tk[i+32]
	}

	for round := 0; round < skinnyRounds; round++ {
		skinnyAddKey(&dummy, &keyCells)
	}

	for round := skinnyRounds - 1; round >= 0; round-- {
		skinnyMixColumnsInv(&state)
		skinnyShiftRowsInv(&state)
		skinnyAddKeyInv(&state, &keyCells)
		skinnyAddConstants(&state, round)
		skinnySubCellsInv(&state)
	}

	for i := 0; i < skinnyBlockSize; i++ {
		out[i] = state[i>>2][i&3]
	}
}

func (b *skinnyBlock) xor(other *skinnyBlock) {
	for i := 0; i < skinnyBlockSize; i++ {
		b[i] ^= other[i]
	}
}

func (b *skinnyBlock) xorBytes(v []byte) {
	for i := 0; i < skinnyBlockSize; i++ {
		b[i] ^= v[i]
	}
}

func (b *skinnyBlock) clear() {
	for i := range b {
		b[i] = 0
	}
}

var skinnySbox = [256]byte{
	0x65, 0x4c, 0x6a, 0x42, 0x4b, 0x63, 0x43, 0x6b,
	0x55, 0x75, 0x5a, 0x7a, 0x53, 0x73, 0x5b, 0x7b,
	0x35, 0x8c, 0x3a, 0x81, 0x89, 0x33, 0x80, 0x3b,
	0x95, 0x25, 0x98, 0x2a, 0x90, 0x23, 0x99, 0x2b,
	0xe5, 0xcc, 0xe8, 0xc1, 0xc9, 0xe0, 0xc0, 0xe9,
	0xd5, 0xf5, 0xd8, 0xf8, 0xd0, 0xf0, 0xd9, 0xf9,
	0xa5, 0x1c, 0xa8, 0x12, 0x1b, 0xa0, 0x13, 0xa9,
	0x05, 0xb5, 0x0a, 0xb8, 0x03, 0xb0, 0x0b, 0xb9,
	0x32, 0x88, 0x3c, 0x85, 0x8d, 0x34, 0x84, 0x3d,
	0x91, 0x22, 0x9c, 0x2c, 0x94, 0x24, 0x9d, 0x2d,
	0x62, 0x4a, 0x6c, 0x45, 0x4d, 0x64, 0x44, 0x6d,
	0x52, 0x72, 0x5c, 0x7c, 0x54, 0x74, 0x5d, 0x7d,
	0xa1, 0x1a, 0xac, 0x15, 0x1d, 0xa4, 0x14, 0xad,
	0x02, 0xb1, 0x0c, 0xbc, 0x04, 0xb4, 0x0d, 0xbd,
	0xe1, 0xc8, 0xec, 0xc5, 0xcd, 0xe4, 0xc4, 0xed,
	0xd1, 0xf1, 0xdc, 0xfc, 0xd4, 0xf4, 0xdd, 0xfd,
	0x36, 0x8e, 0x38, 0x82, 0x8b, 0x30, 0x83, 0x39,
	0x96, 0x26, 0x9a, 0x28, 0x93, 0x20, 0x9b, 0x29,
	0x66, 0x4e, 0x68, 0x41, 0x49, 0x60, 0x40, 0x69,
	0x56, 0x76, 0x58, 0x78, 0x50, 0x70, 0x59, 0x79,
	0xa6, 0x1e, 0xaa, 0x11, 0x19, 0xa3, 0x10, 0xab,
	0x06, 0xb6, 0x08, 0xba, 0x00, 0xb3, 0x09, 0xbb,
	0xe6, 0xce, 0xea, 0xc2, 0xcb, 0xe3, 0xc3, 0xeb,
	0xd6, 0xf6, 0xda, 0xfa, 0xd3, 0xf3, 0xdb, 0xfb,
	0x31, 0x8a, 0x3e, 0x86, 0x8f, 0x37, 0x87, 0x3f,
	0x92, 0x21, 0x9e, 0x2e, 0x97, 0x27, 0x9f, 0x2f,
	0x61, 0x48, 0x6e, 0x46, 0x4f, 0x67, 0x47, 0x6f,
	0x51, 0x71, 0x5e, 0x7e, 0x57, 0x77, 0x5f, 0x7f,
	0xa2, 0x18, 0xae, 0x16, 0x1f, 0xa7, 0x17, 0xaf,
	0x01, 0xb2, 0x0e, 0xbe, 0x07, 0xb7, 0x0f, 0xbf,
	0xe2, 0xca, 0xee, 0xc6, 0xcf, 0xe7, 0xc7, 0xef,
	0xd2, 0xf2, 0xde, 0xfe, 0xd7, 0xf7, 0xdf, 0xff,
}

var skinnySboxInv = [256]byte{
	0xac, 0xe8, 0x68, 0x3c, 0x6c, 0x38, 0xa8, 0xec,
	0xaa, 0xae, 0x3a, 0x3e, 0x6a, 0x6e, 0xea, 0xee,
	0xa6, 0xa3, 0x33, 0x36, 0x66, 0x63, 0xe3, 0xe6,
	0xe1, 0xa4, 0x61, 0x34, 0x31, 0x64, 0xa1, 0xe4,
	0x8d, 0xc9, 0x49, 0x1d, 0x4d, 0x19, 0x89, 0xcd,
	0x8b, 0x8f, 0x1b, 0x1f, 0x4b, 0x4f, 0xcb, 0xcf,
	0x85, 0xc0, 0x40, 0x15, 0x45, 0x10, 0x80, 0xc5,
	0x82, 0x87, 0x12, 0x17, 0x42, 0x47, 0xc2, 0xc7,
	0x96, 0x93, 0x03, 0x06, 0x56, 0x53, 0xd3, 0xd6,
	0xd1, 0x94, 0x51, 0x04, 0x01, 0x54, 0x91, 0xd4,
	0x9c, 0xd8, 0x58, 0x0c, 0x5c, 0x08, 0x98, 0xdc,
	0x9a, 0x9e, 0x0a, 0x0e, 0x5a, 0x5e, 0xda, 0xde,
	0x95, 0xd0, 0x50, 0x05, 0x55, 0x00, 0x90, 0xd5,
	0x92, 0x97, 0x02, 0x07, 0x52, 0x57, 0xd2, 0xd7,
	0x9d, 0xd9, 0x59, 0x0d, 0x5d, 0x09, 0x99, 0xdd,
	0x9b, 0x9f, 0x0b, 0x0f, 0x5b, 0x5f, 0xdb, 0xdf,
	0x16, 0x13, 0x83, 0x86, 0x46, 0x43, 0xc3, 0xc6,
	0x41, 0x14, 0xc1, 0x84, 0x11, 0x44, 0x81, 0xc4,
	0x1c, 0x48, 0xc8, 0x8c, 0x4c, 0x18, 0x88, 0xcc,
	0x1a, 0x1e, 0x8a, 0x8e, 0x4a, 0x4e, 0xca, 0xce,
	0x35, 0x60, 0xe0, 0xa5, 0x65, 0x30, 0xa0, 0xe5,
	0x32, 0x37, 0xa2, 0xa7, 0x62, 0x67, 0xe2, 0xe7,
	0x3d, 0x69, 0xe9, 0xad, 0x6d, 0x39, 0xa9, 0xed,
	0x3b, 0x3f, 0xab, 0xaf, 0x6b, 0x6f, 0xeb, 0xef,
	0x26, 0x23, 0xb3, 0xb6, 0x76, 0x73, 0xf3, 0xf6,
	0x71, 0x24, 0xf1, 0xb4, 0x21, 0x74, 0xb1, 0xf4,
	0x2c, 0x78, 0xf8, 0xbc, 0x7c, 0x28, 0xb8, 0xfc,
	0x2a, 0x2e, 0xba, 0xbe, 0x7a, 0x7e, 0xfa, 0xfe,
	0x25, 0x70, 0xf0, 0xb5, 0x75, 0x20, 0xb0, 0xf5,
	0x22, 0x27, 0xb2, 0xb7, 0x72, 0x77, 0xf2, 0xf7,
	0x2d, 0x79, 0xf9, 0xbd, 0x7d, 0x29, 0xb9, 0xfd,
	0x2b, 0x2f, 0xbb, 0xbf, 0x7b, 0x7f, 0xfb, 0xff,
}

var skinnyTweakeyPerm = [16]byte{9, 15, 8, 13, 10, 14, 12, 11, 0, 1, 2, 3, 4, 5, 6, 7}
var skinnyTweakeyPermInv = [16]byte{8, 9, 10, 11, 12, 13, 14, 15, 2, 0, 4, 7, 6, 3, 5, 1}

var skinnyShiftPerm = [16]byte{0, 1, 2, 3, 7, 4, 5, 6, 10, 11, 8, 9, 13, 14, 15, 12}
var skinnyShiftPermInv = [16]byte{0, 1, 2, 3, 5, 6, 7, 4, 10, 11, 8, 9, 15, 12, 13, 14}

var skinnyRoundConstants = [skinnyRounds]byte{
	0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3e, 0x3d, 0x3b,
	0x37, 0x2f, 0x1e, 0x3c, 0x39, 0x33, 0x27, 0x0e,
	0x1d, 0x3a, 0x35, 0x2b, 0x16, 0x2c, 0x18, 0x30,
	0x21, 0x02, 0x05, 0x0b, 0x17, 0x2e, 0x1c, 0x38,
	0x31, 0x23, 0x06, 0x0d, 0x1b, 0x36, 0x2d, 0x1a,
	0x34, 0x29, 0x12, 0x24, 0x08, 0x11, 0x22, 0x04,
	0x09, 0x13, 0x26, 0x0c, 0x19, 0x32, 0x25, 0x0a,
}

func skinnySubCells(state *[4][4]byte) {
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			state[i][j] = skinnySbox[state[i][j]]
		}
	}
}

func skinnySubCellsInv(state *[4][4]byte) {
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			state[i][j] = skinnySboxInv[state[i][j]]
		}
	}
}

func skinnyShiftRows(state *[4][4]byte) {
	var tmp [4][4]byte
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			pos := skinnyShiftPerm[j+4*i]
			tmp[i][j] = state[pos>>2][pos&3]
		}
	}
	*state = tmp
}

func skinnyShiftRowsInv(state *[4][4]byte) {
	var tmp [4][4]byte
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			pos := skinnyShiftPermInv[j+4*i]
			tmp[i][j] = state[pos>>2][pos&3]
		}
	}
	*state = tmp
}

func skinnyMixColumns(state *[4][4]byte) {
	for j := 0; j < 4; j++ {
		state[1][j] ^= state[2][j]
		state[2][j] ^= state[0][j]
		state[3][j] ^= state[2][j]

		tmp := state[3][j]
		state[3][j] = state[2][j]
		state[2][j] = state[1][j]
		state[1][j] = state[0][j]
		state[0][j] = tmp
	}
}

func skinnyMixColumnsInv(state *[4][4]byte) {
	for j := 0; j < 4; j++ {
		tmp := state[3][j]
		state[3][j] = state[0][j]
		state[0][j] = state[1][j]
		state[1][j] = state[2][j]
		state[2][j] = tmp

		state[3][j] ^= state[2][j]
		state[2][j] ^= state[0][j]
		state[1][j] ^= state[2][j]
	}
}

func skinnyAddConstants(state *[4][4]byte, round int) {
	state[0][0] ^= skinnyRoundConstants[round] & 0x0f
	state[1][0] ^= (skinnyRoundConstants[round] >> 4) & 0x03
	state[2][0] ^= 0x02
}

func skinnyAddKey(state *[4][4]byte, keyCells *[3][4][4]byte) {
	for i := 0; i < 2; i++ {
		for j := 0; j < 4; j++ {
			state[i][j] ^= keyCells[0][i][j] ^ keyCells[1][i][j] ^ keyCells[2][i][j]
		}
	}

	var tmp [3][4][4]byte
	for k := 0; k < 3; k++ {
		for i := 0; i < 4; i++ {
			for j := 0; j < 4; j++ {
				pos := skinnyTweakeyPerm[j+4*i]
				tmp[k][i][j] = keyCells[k][pos>>2][pos&3]
			}
		}
	}

	for i := 0; i < 2; i++ {
		for j := 0; j < 4; j++ {
			tmp[1][i][j] = ((tmp[1][i][j] << 1) & 0xfe) ^ ((tmp[1][i][j] >> 7) & 0x01) ^ ((tmp[1][i][j] >> 5) & 0x01)
			tmp[2][i][j] = ((tmp[2][i][j] >> 1) & 0x7f) ^ ((tmp[2][i][j] << 7) & 0x80) ^ ((tmp[2][i][j] << 1) & 0x80)
		}
	}

	*keyCells = tmp
}

func skinnyAddKeyInv(state *[4][4]byte, keyCells *[3][4][4]byte) {
	var tmp [3][4][4]byte
	for k := 0; k < 3; k++ {
		for i := 0; i < 4; i++ {
			for j := 0; j < 4; j++ {
				pos := skinnyTweakeyPermInv[j+4*i]
				tmp[k][i][j] = keyCells[k][pos>>2][pos&3]
			}
		}
	}

	for i := 0; i < 2; i++ {
		for j := 0; j < 4; j++ {
			tmp[1][i][j] = ((tmp[1][i][j] >> 1) & 0x7f) ^ ((tmp[1][i][j] << 7) & 0x80) ^ ((tmp[1][i][j] << 1) & 0x80)
			tmp[2][i][j] = ((tmp[2][i][j] << 1) & 0xfe) ^ ((tmp[2][i][j] >> 7) & 0x01) ^ ((tmp[2][i][j] >> 5) & 0x01)
		}
	}

	*keyCells = tmp

	for i := 0; i < 2; i++ {
		for j := 0; j < 4; j++ {
			state[i][j] ^= keyCells[0][i][j] ^ keyCells[1][i][j] ^ keyCells[2][i][j]
		}
	}
}
