package poly1305

import (
	"encoding/binary"
	"math/bits"
)

func newMACGeneric(key *[32]byte) macGeneric {
	m := macGeneric{}
	initialize(key, &m.macState)
	return m
}

// macState holds numbers in saturated 64-bit little-endian limbs. That is,
// the value of [x0, x1, x2] is x[0] + x[1] * 2⁶⁴ + x[2] * 2¹²⁸.
type macState struct {
	// h is the main accumulator. It is to be interpreted modulo 2¹³⁰ - 5, but
	// can grow larger during and after rounds. It must, however, remain below
	// 2 * (2¹³⁰ - 5).
	h [3]uint64
	// r and s are the private key components.
	r [2]uint64
	s [2]uint64
}

type macGeneric struct {
	macState

	buffer [TagSize]byte
	offset int
}

// Write splits the incoming message into TagSize chunks, and passes them to
// update. It buffers incomplete chunks.
func (h *macGeneric) Write(p []byte) (int, error) {
	nn := len(p)
	if h.offset > 0 {
		n := copy(h.buffer[h.offset:], p)
		if h.offset+n < TagSize {
			h.offset += n
			return nn, nil
		}
		p = p[n:]
		h.offset = 0
		updateGeneric(&h.macState, h.buffer[:])
	}
	if n := len(p) - (len(p) % TagSize); n > 0 {
		updateGeneric(&h.macState, p[:n])
		p = p[n:]
	}
	if len(p) > 0 {
		h.offset += copy(h.buffer[h.offset:], p)
	}
	return nn, nil
}

// Sum flushes the last incomplete chunk from the buffer, if any, and generates
// the MAC output. It does not modify its state, in order to allow for multiple
// calls to Sum, even if no Write is allowed after Sum.
func (h *macGeneric) Sum(out *[TagSize]byte) {
	state := h.macState
	if h.offset > 0 {
		updateGeneric(&state, h.buffer[:h.offset])
	}
	finalize(out, &state.h, &state.s)
}

// [rMask0, rMask1] is the specified Poly1305 clamping mask in little-endian. It
// clears some bits of the secret coefficient to make it possible to implement
// multiplication more efficiently.
const (
	rMask0 = 0x0FFFFFFC0FFFFFFF
	rMask1 = 0x0FFFFFFC0FFFFFFC
)

// initialize loads the 256-bit key into the two 128-bit secret values r and s.
func initialize(key *[32]byte, m *macState) {
	m.r[0] = binary.LittleEndian.Uint64(key[0:8]) & rMask0
	m.r[1] = binary.LittleEndian.Uint64(key[8:16]) & rMask1
	m.s[0] = binary.LittleEndian.Uint64(key[16:24])
	m.s[1] = binary.LittleEndian.Uint64(key[24:32])
}

// uint128 holds a 128-bit number as two 64-bit limbs, for use with the
// bits.Mul64 and bits.Add64 intrinsics.
type uint128 struct {
	lo, hi uint64
}

func mul64(a, b uint64) uint128 {
	hi, lo := bits.Mul64(a, b)
	return uint128{lo, hi}
}

func add128(a, b uint128) uint128 {
	lo, c := bits.Add64(a.lo, b.lo, 0)
	hi, c := bits.Add64(a.hi, b.hi, c)
	if c != 0 {
		panic("poly1305: unexpected overflow")
	}
	return uint128{lo, hi}
}

func shiftRightBy2(a uint128) uint128 {
	a.lo = a.lo>>2 | (a.hi&3)<<62
	a.hi = a.hi >> 2
	return a
}

// updateGeneric absorbs msg into the state.h accumulator. For each chunk m of
// 128 bits of message, it computes
//
//	h₊ = (h + m) * r  mod  2¹³⁰ - 5
//
// If the msg length is not a multiple of TagSize, it assumes the last
// incomplete chunk is the final one.
func updateGeneric(state *macState, msg []byte) {
	h0, h1, h2 := state.h[0], state.h[1], state.h[2]
	r0, r1 := state.r[0], state.r[1]

	for len(msg) > 0 {
		var c uint64

		if len(msg) >= TagSize {
			h0, c = bits.Add64(h0, binary.LittleEndian.Uint64(msg[0:8]), 0)
			h1, c = bits.Add64(h1, binary.LittleEndian.Uint64(msg[8:16]), c)
			h2 += c + 1

			msg = msg[TagSize:]
		} else {
			var buf [TagSize]byte
			copy(buf[:], msg)
			buf[len(msg)] = 1

			h0, c = bits.Add64(h0, binary.LittleEndian.Uint64(buf[0:8]), 0)
			h1, c = bits.Add64(h1, binary.LittleEndian.Uint64(buf[8:16]), c)
			h2 += c

			msg = nil
		}

		h0r0 := mul64(h0, r0)
		h1r0 := mul64(h1, r0)
		h2r0 := mul64(h2, r0)
		h0r1 := mul64(h0, r1)
		h1r1 := mul64(h1, r1)
		h2r1 := mul64(h2, r1)

		if h2r0.hi != 0 {
			panic("poly1305: unexpected overflow")
		}
		if h2r1.hi != 0 {
			panic("poly1305: unexpected overflow")
		}

		m0 := h0r0
		m1 := add128(h1r0, h0r1) // These two additions don't overflow thanks again
		m2 := add128(h2r0, h1r1) // to the 4 masked bits at the top of r0 and r1.
		m3 := h2r1

		t0 := m0.lo
		t1, c := bits.Add64(m1.lo, m0.hi, 0)
		t2, c := bits.Add64(m2.lo, m1.hi, c)
		t3, _ := bits.Add64(m3.lo, m2.hi, c)

		h0, h1, h2 = t0, t1, t2&maskLow2Bits
		cc := uint128{t2 & maskNotLow2Bits, t3}

		h0, c = bits.Add64(h0, cc.lo, 0)
		h1, c = bits.Add64(h1, cc.hi, c)
		h2 += c

		cc = shiftRightBy2(cc)

		h0, c = bits.Add64(h0, cc.lo, 0)
		h1, c = bits.Add64(h1, cc.hi, c)
		h2 += c
	}

	state.h[0], state.h[1], state.h[2] = h0, h1, h2
}

const (
	maskLow2Bits    uint64 = 0x0000000000000003
	maskNotLow2Bits uint64 = ^maskLow2Bits
)

// select64 returns x if v == 1 and y if v == 0, in constant time.
func select64(v, x, y uint64) uint64 { return ^(v-1)&x | (v-1)&y }

// [p0, p1, p2] is 2¹³⁰ - 5 in little endian order.
const (
	p0 = 0xFFFFFFFFFFFFFFFB
	p1 = 0xFFFFFFFFFFFFFFFF
	p2 = 0x0000000000000003
)

// finalize completes the modular reduction of h and computes
//
//	out = h + s  mod  2¹²⁸
func finalize(out *[TagSize]byte, h *[3]uint64, s *[2]uint64) {
	h0, h1, h2 := h[0], h[1], h[2]

	hMinusP0, b := bits.Sub64(h0, p0, 0)
	hMinusP1, b := bits.Sub64(h1, p1, b)
	_, b = bits.Sub64(h2, p2, b)

	// h = h if h < p else h - p
	h0 = select64(b, h0, hMinusP0)
	h1 = select64(b, h1, hMinusP1)

	h0, c := bits.Add64(h0, s[0], 0)
	h1, _ = bits.Add64(h1, s[1], c)

	binary.LittleEndian.PutUint64(out[0:8], h0)
	binary.LittleEndian.PutUint64(out[8:16], h1)
}
