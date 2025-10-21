package xoodyak

import (
	"encoding/binary"
	"errors"
	"math/bits"
)

// Implementation note: mirrored from the XKCP reference (Cyclist/Xoodoo plain
// variant, little-endian SETBYTE/PAD conventions). Constants therefore appear
// different from the spec's big-endian figures but map to the same byte
// strings described in the Xoodyak specification.

const (
	KeySize          = 16
	NonceSize        = 16
	TagSize          = 16
	FBPrime          = 48
	HashRate         = 16
	KeyRate          = 44
	KeyedSqueezeRate = 24
	LRatchet         = 16
	modeHash         = 1
	modeKeyed        = 2
	phaseDown        = 1
	phaseUp          = 2
)

var roundConstants = [12]uint32{
	0x00000058,
	0x00000038,
	0x000003C0,
	0x000000D0,
	0x00000120,
	0x00000014,
	0x00000060,
	0x0000002C,
	0x00000380,
	0x000000F0,
	0x000001A0,
	0x00000012,
}

type state struct {
	lanes [12]uint32
}

// addByte adds the given byte to the state, starting at the given offset.
func (s *state) addByte(b byte, offset int) {
	lane := offset / 4
	shift := (offset % 4) * 8
	s.lanes[lane] ^= uint32(b) << shift
}

// addBytes adds the given bytes to the state, starting at the given offset.
func (s *state) addBytes(data []byte, offset int) {
	if len(data) == 0 {
		return
	}
	state := s.lanes[:]
	idx := 0
	lanePos := offset / 4
	offsetInLane := offset % 4
	if offsetInLane != 0 {
		bytesInLane := 4 - offsetInLane
		if bytesInLane > len(data) {
			bytesInLane = len(data)
		}
		var lane uint32
		for i := 0; i < bytesInLane; i++ {
			lane |= uint32(data[i]) << (8 * (offsetInLane + i))
		}
		state[lanePos] ^= lane
		lanePos++
		idx += bytesInLane
	}
	for len(data)-idx >= 4 {
		lane := binary.LittleEndian.Uint32(data[idx:])
		state[lanePos] ^= lane
		lanePos++
		idx += 4
	}
	if idx < len(data) {
		var lane uint32
		for i := 0; idx+i < len(data); i++ {
			lane |= uint32(data[idx+i]) << (8 * i)
		}
		state[lanePos] ^= lane
	}
}

// extractBytes extracts bytes from the state and stores them in the given buffer, starting at the given offset.
func (s *state) extractBytes(dst []byte, offset int) {
	if len(dst) == 0 {
		return
	}
	state := s.lanes[:]
	idx := 0
	lanePos := offset / 4
	offsetInLane := offset % 4
	if offsetInLane != 0 {
		bytesInLane := 4 - offsetInLane
		if bytesInLane > len(dst) {
			bytesInLane = len(dst)
		}
		lane := state[lanePos] >> (offsetInLane * 8)
		for i := 0; i < bytesInLane; i++ {
			dst[idx] = byte(lane)
			lane >>= 8
			idx++
		}
		lanePos++
	}
	remaining := len(dst) - idx
	for remaining >= 4 {
		binary.LittleEndian.PutUint32(dst[idx:], state[lanePos])
		idx += 4
		lanePos++
		remaining -= 4
	}
	if remaining > 0 {
		lane := state[lanePos]
		for i := 0; i < remaining; i++ {
			dst[idx+i] = byte(lane)
			lane >>= 8
		}
	}
}

// extractAndAddBytes extracts bytes from the state and XORs them with the given bytes, starting at the given offset.
func (s *state) extractAndAddBytes(input, output []byte, offset int) {
	if len(input) != len(output) {
		panic("xoodyak: mismatched buffers")
	}
	if len(input) == 0 {
		return
	}
	state := s.lanes[:]
	idx := 0
	lanePos := offset / 4
	offsetInLane := offset % 4
	if offsetInLane != 0 {
		bytesInLane := 4 - offsetInLane
		if bytesInLane > len(input) {
			bytesInLane = len(input)
		}
		lane := state[lanePos] >> (offsetInLane * 8)
		for i := 0; i < bytesInLane; i++ {
			output[idx] = input[idx] ^ byte(lane)
			lane >>= 8
			idx++
		}
		lanePos++
	}
	remaining := len(input) - idx
	for remaining >= 4 {
		lane := state[lanePos]
		val := binary.LittleEndian.Uint32(input[idx:])
		binary.LittleEndian.PutUint32(output[idx:], val^lane)
		idx += 4
		lanePos++
		remaining -= 4
	}
	if remaining > 0 {
		lane := state[lanePos]
		for i := 0; i < remaining; i++ {
			output[idx+i] = input[idx+i] ^ byte(lane)
			lane >>= 8
		}
	}
}

// permute performs the Xoodyak permutation on the state.
func (s *state) permute() {
	a := s.lanes
	a00 := a[0]
	a01 := a[1]
	a02 := a[2]
	a03 := a[3]
	a10 := a[4]
	a11 := a[5]
	a12 := a[6]
	a13 := a[7]
	a20 := a[8]
	a21 := a[9]
	a22 := a[10]
	a23 := a[11]

	for _, rc := range roundConstants {
		v1 := a03 ^ a13 ^ a23
		v2 := a00 ^ a10 ^ a20
		v1 = bits.RotateLeft32(v1, 5) ^ bits.RotateLeft32(v1, 14)
		a00 ^= v1
		a10 ^= v1
		a20 ^= v1
		v1 = a01 ^ a11 ^ a21
		v2 = bits.RotateLeft32(v2, 5) ^ bits.RotateLeft32(v2, 14)
		a01 ^= v2
		a11 ^= v2
		a21 ^= v2
		v2 = a02 ^ a12 ^ a22
		v1 = bits.RotateLeft32(v1, 5) ^ bits.RotateLeft32(v1, 14)
		a02 ^= v1
		a12 ^= v1
		a22 ^= v1
		v2 = bits.RotateLeft32(v2, 5) ^ bits.RotateLeft32(v2, 14)
		a03 ^= v2
		a13 ^= v2
		a23 ^= v2

		a20 = bits.RotateLeft32(a20, 11)
		a21 = bits.RotateLeft32(a21, 11)
		a22 = bits.RotateLeft32(a22, 11)
		a23 = bits.RotateLeft32(a23, 11)
		v1 = a13
		a13 = a12
		a12 = a11
		a11 = a10
		a10 = v1

		a00 ^= rc

		a00 ^= ^a10 & a20
		a10 ^= ^a20 & a00
		a20 ^= ^a00 & a10

		a01 ^= ^a11 & a21
		a11 ^= ^a21 & a01
		a21 ^= ^a01 & a11

		a02 ^= ^a12 & a22
		a12 ^= ^a22 & a02
		a22 ^= ^a02 & a12

		a03 ^= ^a13 & a23
		a13 ^= ^a23 & a03
		a23 ^= ^a03 & a13

		a10 = bits.RotateLeft32(a10, 1)
		a11 = bits.RotateLeft32(a11, 1)
		a12 = bits.RotateLeft32(a12, 1)
		a13 = bits.RotateLeft32(a13, 1)
		v1 = bits.RotateLeft32(a23, 8)
		a23 = bits.RotateLeft32(a21, 8)
		a21 = v1
		v1 = bits.RotateLeft32(a22, 8)
		a22 = bits.RotateLeft32(a20, 8)
		a20 = v1
	}

	s.lanes = [12]uint32{
		a00, a01, a02, a03,
		a10, a11, a12, a13,
		a20, a21, a22, a23,
	}
}

type Instance struct {
	state    state
	phase    int
	mode     int
	rAbsorb  int
	rSqueeze int
}

// initialize initializes the Xoodyak instance with the given key, id, and counter.
func (x *Instance) Initialize(key, id, counter []byte) error {
	x.state = state{}
	x.phase = phaseUp
	x.mode = modeHash
	x.rAbsorb = HashRate
	x.rSqueeze = HashRate
	if len(key) > 0 {
		if err := x.absorbKey(key, id, counter); err != nil {
			return err
		}
	}
	return nil
}

// absorbKey absorbs the key, id, and counter into the Xoodyak state.
func (x *Instance) absorbKey(key, id, counter []byte) error {
	if len(key)+len(id) > KeyRate-1 {
		return errors.New("xoodyak: len(key)+len(id) exceeds rKin-1")
	}
	x.mode = modeKeyed
	x.rAbsorb = KeyRate
	x.rSqueeze = KeyedSqueezeRate
	if len(key) == 0 {
		return nil
	}
	var kid [KeyRate]byte
	copy(kid[:], key)
	copy(kid[len(key):], id)
	kid[len(key)+len(id)] = byte(len(id))
	x.absorbAny(kid[:len(key)+len(id)+1], x.rAbsorb, 0x02)
	if len(counter) > 0 {
		x.absorbAny(counter, 1, 0x00)
	}
	return nil
}

// absorbAny is a wrapper around the Xoodyak-Absorbing mode that allows the caller to specify the control byte.
func (x *Instance) absorbAny(data []byte, rate int, cd byte) {
	first := true
	for first || len(data) != 0 {
		if x.phase != phaseUp {
			x.up(nil, 0, 0)
		}
		split := min(len(data), rate)
		x.down(data[:split], split, cd)
		cd = 0
		if split > 0 {
			data = data[split:]
		}
		first = false
		if len(data) == 0 {
			break
		}
	}
}

// down is a wrapper around the Xoodyak-Squeezing mode that allows the caller to specify the control byte.
func (x *Instance) down(data []byte, xiLen int, cd byte) {
	x.state.addBytes(data, 0)
	x.state.addByte(0x01, xiLen)
	if x.mode == modeHash {
		x.state.addByte(cd&0x01, FBPrime-1)
	} else {
		x.state.addByte(cd, FBPrime-1)
	}
	x.phase = phaseDown
}

// up is a wrapper around the Xoodyak-Absorbing mode that allows the caller to specify the control byte.
func (x *Instance) up(dst []byte, yiLen int, cu byte) {
	if x.mode != modeHash {
		// In Cyclist the first Up after a Down in keyed mode XORs a control byte;
		// 0x80 marks the first block, and subsequent blocks use 0.
		x.state.addByte(cu, FBPrime-1)
	}
	x.state.permute()
	x.phase = phaseUp
	if yiLen > 0 {
		x.state.extractBytes(dst[:yiLen], 0)
	}
}

func (x *Instance) Absorb(data []byte) {
	x.absorbAny(data, x.rAbsorb, 0x03)
}

// squeezeAny is a wrapper around the Xoodyak-Squeezing mode that allows the caller to specify the control byte.
func (x *Instance) SqueezeAny(dst []byte, cu byte) {
	if len(dst) == 0 {
		return
	}
	lenThis := min(len(dst), x.rSqueeze)
	x.up(dst[:lenThis], lenThis, cu)
	dst = dst[lenThis:]
	for len(dst) != 0 {
		x.down(nil, 0, 0)
		lenThis = min(len(dst), x.rSqueeze)
		x.up(dst[:lenThis], lenThis, 0)
		dst = dst[lenThis:]
	}
}

// squeeze is a wrapper around squeezeAny that uses the Cyclist domain separator for keyed squeezing (tags).
func (x *Instance) Squeeze(dst []byte) {
	// 0x40 is the Cyclist domain separator for keyed squeezing (tags).
	x.SqueezeAny(dst, 0x40)
}

func (x *Instance) Crypt(in, out []byte, decrypt bool) {
	if len(in) != len(out) {
		panic("xoodyak: mismatched buffers")
	}
	var temp [KeyedSqueezeRate]byte
	cu := byte(0x80)
	first := true
	remaining := len(in)
	for first || remaining > 0 {
		split := min(remaining, KeyedSqueezeRate)
		x.up(nil, 0, cu)
		if decrypt {
			// Cyclist decrypt absorbs the recovered plaintext to stay aligned with the encryption path.
			x.state.extractAndAddBytes(in[:split], out[:split], 0)
			x.down(out[:split], split, 0x00)
		} else {
			copy(temp[:split], in[:split])
			x.state.extractAndAddBytes(in[:split], out[:split], 0)
			x.down(temp[:split], split, 0x00)
		}
		if split > 0 {
			in = in[split:]
			out = out[split:]
			remaining -= split
		}
		cu = 0x00
		first = false
	}
	for i := range temp {
		temp[i] = 0
	}
}

// Advance executes a zero-length Down step, preparing for additional squeezing.
func (x *Instance) Advance() {
	x.down(nil, 0, 0)
}

// Clear zeroes the internal state and resets control flags.
func (x *Instance) Clear() {
	x.state = state{}
	x.phase = 0
	x.mode = 0
	x.rAbsorb = 0
	x.rSqueeze = 0
}
