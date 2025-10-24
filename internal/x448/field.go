// Package x448 provides constant-time field arithmetic and scalar
// multiplication for Curve448. Portions of this file are derived from
// Cloudflare's CIRCL project (https://github.com/cloudflare/circl) which is
// licensed under the BSD 3-Clause "New" or "Revised" License. The code has been
// adapted to fit the needs of the cryptonite-go project.
package x448

import (
	"encoding/binary"
	"math/bits"
)

// Size is the length in bytes of field elements and Curve448 points.
const Size = 56

// fieldElement represents an element of GF(2^448 - 2^224 - 1) in little-endian
// byte form. The representation follows the conventions used by RFC 7748 and
// allows constant-time arithmetic operations.
type fieldElement [Size]byte

var (
	// modulus is the prime p = 2^448 - 2^224 - 1 represented in little endian.
	modulus = fieldElement{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	}
	one = fieldElement{1}
)

func setOne(x *fieldElement) { *x = one }

func add(z, x, y *fieldElement) {
	x0 := binary.LittleEndian.Uint64(x[0*8 : 1*8])
	x1 := binary.LittleEndian.Uint64(x[1*8 : 2*8])
	x2 := binary.LittleEndian.Uint64(x[2*8 : 3*8])
	x3 := binary.LittleEndian.Uint64(x[3*8 : 4*8])
	x4 := binary.LittleEndian.Uint64(x[4*8 : 5*8])
	x5 := binary.LittleEndian.Uint64(x[5*8 : 6*8])
	x6 := binary.LittleEndian.Uint64(x[6*8 : 7*8])

	y0 := binary.LittleEndian.Uint64(y[0*8 : 1*8])
	y1 := binary.LittleEndian.Uint64(y[1*8 : 2*8])
	y2 := binary.LittleEndian.Uint64(y[2*8 : 3*8])
	y3 := binary.LittleEndian.Uint64(y[3*8 : 4*8])
	y4 := binary.LittleEndian.Uint64(y[4*8 : 5*8])
	y5 := binary.LittleEndian.Uint64(y[5*8 : 6*8])
	y6 := binary.LittleEndian.Uint64(y[6*8 : 7*8])

	z0, c0 := bits.Add64(x0, y0, 0)
	z1, c1 := bits.Add64(x1, y1, c0)
	z2, c2 := bits.Add64(x2, y2, c1)
	z3, c3 := bits.Add64(x3, y3, c2)
	z4, c4 := bits.Add64(x4, y4, c3)
	z5, c5 := bits.Add64(x5, y5, c4)
	z6, z7 := bits.Add64(x6, y6, c5)

	z0, c0 = bits.Add64(z0, z7, 0)
	z1, c1 = bits.Add64(z1, 0, c0)
	z2, c2 = bits.Add64(z2, 0, c1)
	z3, c3 = bits.Add64(z3, z7<<32, c2)
	z4, c4 = bits.Add64(z4, 0, c3)
	z5, c5 = bits.Add64(z5, 0, c4)
	z6, z7 = bits.Add64(z6, 0, c5)

	z0, c0 = bits.Add64(z0, z7, 0)
	z1, c1 = bits.Add64(z1, 0, c0)
	z2, c2 = bits.Add64(z2, 0, c1)
	z3, c3 = bits.Add64(z3, z7<<32, c2)
	z4, c4 = bits.Add64(z4, 0, c3)
	z5, c5 = bits.Add64(z5, 0, c4)
	z6, _ = bits.Add64(z6, 0, c5)

	binary.LittleEndian.PutUint64(z[0*8:1*8], z0)
	binary.LittleEndian.PutUint64(z[1*8:2*8], z1)
	binary.LittleEndian.PutUint64(z[2*8:3*8], z2)
	binary.LittleEndian.PutUint64(z[3*8:4*8], z3)
	binary.LittleEndian.PutUint64(z[4*8:5*8], z4)
	binary.LittleEndian.PutUint64(z[5*8:6*8], z5)
	binary.LittleEndian.PutUint64(z[6*8:7*8], z6)
}

func sub(z, x, y *fieldElement) {
	x0 := binary.LittleEndian.Uint64(x[0*8 : 1*8])
	x1 := binary.LittleEndian.Uint64(x[1*8 : 2*8])
	x2 := binary.LittleEndian.Uint64(x[2*8 : 3*8])
	x3 := binary.LittleEndian.Uint64(x[3*8 : 4*8])
	x4 := binary.LittleEndian.Uint64(x[4*8 : 5*8])
	x5 := binary.LittleEndian.Uint64(x[5*8 : 6*8])
	x6 := binary.LittleEndian.Uint64(x[6*8 : 7*8])

	y0 := binary.LittleEndian.Uint64(y[0*8 : 1*8])
	y1 := binary.LittleEndian.Uint64(y[1*8 : 2*8])
	y2 := binary.LittleEndian.Uint64(y[2*8 : 3*8])
	y3 := binary.LittleEndian.Uint64(y[3*8 : 4*8])
	y4 := binary.LittleEndian.Uint64(y[4*8 : 5*8])
	y5 := binary.LittleEndian.Uint64(y[5*8 : 6*8])
	y6 := binary.LittleEndian.Uint64(y[6*8 : 7*8])

	z0, c0 := bits.Sub64(x0, y0, 0)
	z1, c1 := bits.Sub64(x1, y1, c0)
	z2, c2 := bits.Sub64(x2, y2, c1)
	z3, c3 := bits.Sub64(x3, y3, c2)
	z4, c4 := bits.Sub64(x4, y4, c3)
	z5, c5 := bits.Sub64(x5, y5, c4)
	z6, z7 := bits.Sub64(x6, y6, c5)

	z0, c0 = bits.Sub64(z0, z7, 0)
	z1, c1 = bits.Sub64(z1, 0, c0)
	z2, c2 = bits.Sub64(z2, 0, c1)
	z3, c3 = bits.Sub64(z3, z7<<32, c2)
	z4, c4 = bits.Sub64(z4, 0, c3)
	z5, c5 = bits.Sub64(z5, 0, c4)
	z6, z7 = bits.Sub64(z6, 0, c5)

	z0, c0 = bits.Sub64(z0, z7, 0)
	z1, c1 = bits.Sub64(z1, 0, c0)
	z2, c2 = bits.Sub64(z2, 0, c1)
	z3, c3 = bits.Sub64(z3, z7<<32, c2)
	z4, c4 = bits.Sub64(z4, 0, c3)
	z5, c5 = bits.Sub64(z5, 0, c4)
	z6, _ = bits.Sub64(z6, 0, c5)

	binary.LittleEndian.PutUint64(z[0*8:1*8], z0)
	binary.LittleEndian.PutUint64(z[1*8:2*8], z1)
	binary.LittleEndian.PutUint64(z[2*8:3*8], z2)
	binary.LittleEndian.PutUint64(z[3*8:4*8], z3)
	binary.LittleEndian.PutUint64(z[4*8:5*8], z4)
	binary.LittleEndian.PutUint64(z[5*8:6*8], z5)
	binary.LittleEndian.PutUint64(z[6*8:7*8], z6)
}

func addSub(x, y *fieldElement) {
	tmp := fieldElement{}
	add(&tmp, x, y)
	sub(y, x, y)
	*x = tmp
}

func mul(z, x, y *fieldElement) {
	x0 := binary.LittleEndian.Uint64(x[0*8 : 1*8])
	x1 := binary.LittleEndian.Uint64(x[1*8 : 2*8])
	x2 := binary.LittleEndian.Uint64(x[2*8 : 3*8])
	x3 := binary.LittleEndian.Uint64(x[3*8 : 4*8])
	x4 := binary.LittleEndian.Uint64(x[4*8 : 5*8])
	x5 := binary.LittleEndian.Uint64(x[5*8 : 6*8])
	x6 := binary.LittleEndian.Uint64(x[6*8 : 7*8])

	y0 := binary.LittleEndian.Uint64(y[0*8 : 1*8])
	y1 := binary.LittleEndian.Uint64(y[1*8 : 2*8])
	y2 := binary.LittleEndian.Uint64(y[2*8 : 3*8])
	y3 := binary.LittleEndian.Uint64(y[3*8 : 4*8])
	y4 := binary.LittleEndian.Uint64(y[4*8 : 5*8])
	y5 := binary.LittleEndian.Uint64(y[5*8 : 6*8])
	y6 := binary.LittleEndian.Uint64(y[6*8 : 7*8])

	yy := [7]uint64{y0, y1, y2, y3, y4, y5, y6}
	zz := [7]uint64{}

	yi := yy[0]
	h0, l0 := bits.Mul64(x0, yi)
	h1, l1 := bits.Mul64(x1, yi)
	h2, l2 := bits.Mul64(x2, yi)
	h3, l3 := bits.Mul64(x3, yi)
	h4, l4 := bits.Mul64(x4, yi)
	h5, l5 := bits.Mul64(x5, yi)
	h6, l6 := bits.Mul64(x6, yi)

	zz[0] = l0
	a0, c0 := bits.Add64(h0, l1, 0)
	a1, c1 := bits.Add64(h1, l2, c0)
	a2, c2 := bits.Add64(h2, l3, c1)
	a3, c3 := bits.Add64(h3, l4, c2)
	a4, c4 := bits.Add64(h4, l5, c3)
	a5, c5 := bits.Add64(h5, l6, c4)
	a6, _ := bits.Add64(h6, 0, c5)

	for i := 1; i < 7; i++ {
		yi = yy[i]
		h0, l0 = bits.Mul64(x0, yi)
		h1, l1 = bits.Mul64(x1, yi)
		h2, l2 = bits.Mul64(x2, yi)
		h3, l3 = bits.Mul64(x3, yi)
		h4, l4 = bits.Mul64(x4, yi)
		h5, l5 = bits.Mul64(x5, yi)
		h6, l6 = bits.Mul64(x6, yi)

		zz[i], c0 = bits.Add64(a0, l0, 0)
		a0, c1 = bits.Add64(a1, l1, c0)
		a1, c2 = bits.Add64(a2, l2, c1)
		a2, c3 = bits.Add64(a3, l3, c2)
		a3, c4 = bits.Add64(a4, l4, c3)
		a4, c5 = bits.Add64(a5, l5, c4)
		a5, a6 = bits.Add64(a6, l6, c5)

		a0, c0 = bits.Add64(a0, h0, 0)
		a1, c1 = bits.Add64(a1, h1, c0)
		a2, c2 = bits.Add64(a2, h2, c1)
		a3, c3 = bits.Add64(a3, h3, c2)
		a4, c4 = bits.Add64(a4, h4, c3)
		a5, c5 = bits.Add64(a5, h5, c4)
		a6, _ = bits.Add64(a6, h6, c5)
	}
	reduce64(z, &zz, &[7]uint64{a0, a1, a2, a3, a4, a5, a6})
}

func sqr(z, x *fieldElement) { mul(z, x, x) }

func reduce64(z *fieldElement, l, h *[7]uint64) {
	h0 := h[0]
	h1 := h[1]
	h2 := h[2]
	h3 := ((h[3] & (0xFFFFFFFF << 32)) << 1) | (h[3] & 0xFFFFFFFF)
	h4 := (h[3] >> 63) | (h[4] << 1)
	h5 := (h[4] >> 63) | (h[5] << 1)
	h6 := (h[5] >> 63) | (h[6] << 1)
	h7 := (h[6] >> 63)

	l0, c0 := bits.Add64(h0, l[0], 0)
	l1, c1 := bits.Add64(h1, l[1], c0)
	l2, c2 := bits.Add64(h2, l[2], c1)
	l3, c3 := bits.Add64(h3, l[3], c2)
	l4, c4 := bits.Add64(h4, l[4], c3)
	l5, c5 := bits.Add64(h5, l[5], c4)
	l6, c6 := bits.Add64(h6, l[6], c5)
	l7, _ := bits.Add64(h7, 0, c6)

	h0 = (h[3] >> 32) | (h[4] << 32)
	h1 = (h[4] >> 32) | (h[5] << 32)
	h2 = (h[5] >> 32) | (h[6] << 32)
	h3 = (h[6] >> 32) | (h[0] << 32)
	h4 = (h[0] >> 32) | (h[1] << 32)
	h5 = (h[1] >> 32) | (h[2] << 32)
	h6 = (h[2] >> 32) | (h[3] << 32)

	l0, c0 = bits.Add64(l0, h0, 0)
	l1, c1 = bits.Add64(l1, h1, c0)
	l2, c2 = bits.Add64(l2, h2, c1)
	l3, c3 = bits.Add64(l3, h3, c2)
	l4, c4 = bits.Add64(l4, h4, c3)
	l5, c5 = bits.Add64(l5, h5, c4)
	l6, c6 = bits.Add64(l6, h6, c5)
	l7, _ = bits.Add64(l7, 0, c6)

	l0, c0 = bits.Add64(l0, l7, 0)
	l1, c1 = bits.Add64(l1, 0, c0)
	l2, c2 = bits.Add64(l2, 0, c1)
	l3, c3 = bits.Add64(l3, l7<<32, c2)
	l4, c4 = bits.Add64(l4, 0, c3)
	l5, c5 = bits.Add64(l5, 0, c4)
	l6, l7 = bits.Add64(l6, 0, c5)

	l0, c0 = bits.Add64(l0, l7, 0)
	l1, c1 = bits.Add64(l1, 0, c0)
	l2, c2 = bits.Add64(l2, 0, c1)
	l3, c3 = bits.Add64(l3, l7<<32, c2)
	l4, c4 = bits.Add64(l4, 0, c3)
	l5, c5 = bits.Add64(l5, 0, c4)
	l6, _ = bits.Add64(l6, 0, c5)

	binary.LittleEndian.PutUint64(z[0*8:1*8], l0)
	binary.LittleEndian.PutUint64(z[1*8:2*8], l1)
	binary.LittleEndian.PutUint64(z[2*8:3*8], l2)
	binary.LittleEndian.PutUint64(z[3*8:4*8], l3)
	binary.LittleEndian.PutUint64(z[4*8:5*8], l4)
	binary.LittleEndian.PutUint64(z[5*8:6*8], l5)
	binary.LittleEndian.PutUint64(z[6*8:7*8], l6)
}

func cmov(x, y *fieldElement, n uint) {
	m := -uint64(n & 0x1)
	x0 := binary.LittleEndian.Uint64(x[0*8 : 1*8])
	x1 := binary.LittleEndian.Uint64(x[1*8 : 2*8])
	x2 := binary.LittleEndian.Uint64(x[2*8 : 3*8])
	x3 := binary.LittleEndian.Uint64(x[3*8 : 4*8])
	x4 := binary.LittleEndian.Uint64(x[4*8 : 5*8])
	x5 := binary.LittleEndian.Uint64(x[5*8 : 6*8])
	x6 := binary.LittleEndian.Uint64(x[6*8 : 7*8])

	y0 := binary.LittleEndian.Uint64(y[0*8 : 1*8])
	y1 := binary.LittleEndian.Uint64(y[1*8 : 2*8])
	y2 := binary.LittleEndian.Uint64(y[2*8 : 3*8])
	y3 := binary.LittleEndian.Uint64(y[3*8 : 4*8])
	y4 := binary.LittleEndian.Uint64(y[4*8 : 5*8])
	y5 := binary.LittleEndian.Uint64(y[5*8 : 6*8])
	y6 := binary.LittleEndian.Uint64(y[6*8 : 7*8])

	x0 = (x0 &^ m) | (y0 & m)
	x1 = (x1 &^ m) | (y1 & m)
	x2 = (x2 &^ m) | (y2 & m)
	x3 = (x3 &^ m) | (y3 & m)
	x4 = (x4 &^ m) | (y4 & m)
	x5 = (x5 &^ m) | (y5 & m)
	x6 = (x6 &^ m) | (y6 & m)

	binary.LittleEndian.PutUint64(x[0*8:1*8], x0)
	binary.LittleEndian.PutUint64(x[1*8:2*8], x1)
	binary.LittleEndian.PutUint64(x[2*8:3*8], x2)
	binary.LittleEndian.PutUint64(x[3*8:4*8], x3)
	binary.LittleEndian.PutUint64(x[4*8:5*8], x4)
	binary.LittleEndian.PutUint64(x[5*8:6*8], x5)
	binary.LittleEndian.PutUint64(x[6*8:7*8], x6)
}

func cswap(x, y *fieldElement, n uint) {
	m := -uint64(n & 0x1)
	x0 := binary.LittleEndian.Uint64(x[0*8 : 1*8])
	x1 := binary.LittleEndian.Uint64(x[1*8 : 2*8])
	x2 := binary.LittleEndian.Uint64(x[2*8 : 3*8])
	x3 := binary.LittleEndian.Uint64(x[3*8 : 4*8])
	x4 := binary.LittleEndian.Uint64(x[4*8 : 5*8])
	x5 := binary.LittleEndian.Uint64(x[5*8 : 6*8])
	x6 := binary.LittleEndian.Uint64(x[6*8 : 7*8])

	y0 := binary.LittleEndian.Uint64(y[0*8 : 1*8])
	y1 := binary.LittleEndian.Uint64(y[1*8 : 2*8])
	y2 := binary.LittleEndian.Uint64(y[2*8 : 3*8])
	y3 := binary.LittleEndian.Uint64(y[3*8 : 4*8])
	y4 := binary.LittleEndian.Uint64(y[4*8 : 5*8])
	y5 := binary.LittleEndian.Uint64(y[5*8 : 6*8])
	y6 := binary.LittleEndian.Uint64(y[6*8 : 7*8])

	t0 := m & (x0 ^ y0)
	t1 := m & (x1 ^ y1)
	t2 := m & (x2 ^ y2)
	t3 := m & (x3 ^ y3)
	t4 := m & (x4 ^ y4)
	t5 := m & (x5 ^ y5)
	t6 := m & (x6 ^ y6)
	x0 ^= t0
	x1 ^= t1
	x2 ^= t2
	x3 ^= t3
	x4 ^= t4
	x5 ^= t5
	x6 ^= t6
	y0 ^= t0
	y1 ^= t1
	y2 ^= t2
	y3 ^= t3
	y4 ^= t4
	y5 ^= t5
	y6 ^= t6

	binary.LittleEndian.PutUint64(x[0*8:1*8], x0)
	binary.LittleEndian.PutUint64(x[1*8:2*8], x1)
	binary.LittleEndian.PutUint64(x[2*8:3*8], x2)
	binary.LittleEndian.PutUint64(x[3*8:4*8], x3)
	binary.LittleEndian.PutUint64(x[4*8:5*8], x4)
	binary.LittleEndian.PutUint64(x[5*8:6*8], x5)
	binary.LittleEndian.PutUint64(x[6*8:7*8], x6)

	binary.LittleEndian.PutUint64(y[0*8:1*8], y0)
	binary.LittleEndian.PutUint64(y[1*8:2*8], y1)
	binary.LittleEndian.PutUint64(y[2*8:3*8], y2)
	binary.LittleEndian.PutUint64(y[3*8:4*8], y3)
	binary.LittleEndian.PutUint64(y[4*8:5*8], y4)
	binary.LittleEndian.PutUint64(y[5*8:6*8], y5)
	binary.LittleEndian.PutUint64(y[6*8:7*8], y6)
}

func modp(z *fieldElement) { sub(z, z, &modulus) }

func inv(z, x *fieldElement) {
	t := fieldElement{}
	powPminus3div4(&t, x)
	sqr(&t, &t)
	sqr(&t, &t)
	mul(z, &t, x)
}

func powPminus3div4(z, x *fieldElement) {
	x0, x1 := fieldElement{}, fieldElement{}
	sqr(z, x)
	mul(z, z, x)
	sqr(&x0, z)
	mul(&x0, &x0, x)
	sqr(z, &x0)
	sqr(z, z)
	sqr(z, z)
	mul(z, z, &x0)
	sqr(&x1, z)
	for i := 0; i < 5; i++ {
		sqr(&x1, &x1)
	}
	mul(&x1, &x1, z)
	sqr(z, &x1)
	for i := 0; i < 11; i++ {
		sqr(z, z)
	}
	mul(z, z, &x1)
	sqr(z, z)
	sqr(z, z)
	sqr(z, z)
	mul(z, z, &x0)
	sqr(&x1, z)
	for i := 0; i < 26; i++ {
		sqr(&x1, &x1)
	}
	mul(&x1, &x1, z)
	sqr(z, &x1)
	for i := 0; i < 53; i++ {
		sqr(z, z)
	}
	mul(z, z, &x1)
	sqr(z, z)
	sqr(z, z)
	sqr(z, z)
	mul(z, z, &x0)
	sqr(&x1, z)
	for i := 0; i < 110; i++ {
		sqr(&x1, &x1)
	}
	mul(&x1, &x1, z)
	sqr(z, &x1)
	mul(z, z, x)
	for i := 0; i < 223; i++ {
		sqr(z, z)
	}
	mul(z, z, &x1)
}

func toBytes(out []byte, x *fieldElement) {
	modp(x)
	copy(out, x[:])
}

func isZero(x *fieldElement) bool {
	modp(x)
	for i := 0; i < Size; i++ {
		if x[i] != 0 {
			return false
		}
	}
	return true
}

func fromBytes(out *fieldElement, in []byte) {
	copy(out[:], in[:Size])
	modp(out)
}
