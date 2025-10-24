package x448

import (
	"crypto/subtle"
	"encoding/binary"
	"math/bits"
)

type key [Size]byte

func clamp(dst *key, in *[Size]byte) {
	copy(dst[:], in[:])
	dst[0] &= 252
	dst[55] |= 128
}

// ScalarMult performs scalar multiplication on Curve448 using the Montgomery
// ladder. The scalar is clamped as per RFC 7748.
func ScalarMult(dst *[Size]byte, scalar, point *[Size]byte) {
	var k key
	clamp(&k, scalar)
	var p key
	copy(p[:], point[:])
	ladderMontgomery(&k, &p)
	copy(dst[:], k[:])
}

// ScalarBaseMult multiplies the canonical base point by the provided scalar.
func ScalarBaseMult(dst *[Size]byte, scalar *[Size]byte) {
	var base = [Size]byte{5}
	ScalarMult(dst, scalar, &base)
}

func ladderMontgomery(k, xP *key) {
	var w [5]fieldElement // [x1, x2, z2, x3, z3]
	w[0] = *(*fieldElement)(xP)
	setOne(&w[1])
	w[3] = *(*fieldElement)(xP)
	setOne(&w[4])

	move := uint(0)
	for s := 448 - 1; s >= 0; s-- {
		i := s / 8
		j := s % 8
		bit := uint((k[i] >> uint(j)) & 1)
		ladderStep(&w, move^bit)
		move = bit
	}
	toAffine((*[Size]byte)(k), &w[1], &w[2])
}

func ladderStep(w *[5]fieldElement, b uint) {
	x1, x2, z2, x3, z3 := &w[0], &w[1], &w[2], &w[3], &w[4]
	t0 := fieldElement{}
	t1 := fieldElement{}
	addSub(x2, z2)
	addSub(x3, z3)
	mul(&t0, x2, z3)
	mul(&t1, x3, z2)
	addSub(&t0, &t1)
	cmov(x2, x3, b)
	cmov(z2, z3, b)
	sqr(x3, &t0)
	sqr(z3, &t1)
	mul(z3, x1, z3)
	sqr(x2, x2)
	sqr(z2, z2)
	sub(&t0, x2, z2)
	mulA24(&t1, &t0)
	add(&t1, &t1, z2)
	mul(x2, x2, z2)
	mul(z2, &t0, &t1)
}

func mulA24(z, x *fieldElement) {
	const A24 = 39082
	const limbBytes = 8
	var words [7]uint64
	for i := range words {
		words[i] = binary.LittleEndian.Uint64(x[i*limbBytes : (i+1)*limbBytes])
	}
	h0, l0 := bits.Mul64(words[0], A24)
	h1, l1 := bits.Mul64(words[1], A24)
	h2, l2 := bits.Mul64(words[2], A24)
	h3, l3 := bits.Mul64(words[3], A24)
	h4, l4 := bits.Mul64(words[4], A24)
	h5, l5 := bits.Mul64(words[5], A24)
	h6, l6 := bits.Mul64(words[6], A24)

	l1, c0 := bits.Add64(h0, l1, 0)
	l2, c1 := bits.Add64(h1, l2, c0)
	l3, c2 := bits.Add64(h2, l3, c1)
	l4, c3 := bits.Add64(h3, l4, c2)
	l5, c4 := bits.Add64(h4, l5, c3)
	l6, c5 := bits.Add64(h5, l6, c4)
	l7, _ := bits.Add64(h6, 0, c5)

	l0, c0 = bits.Add64(l0, l7, 0)
	l1, c1 = bits.Add64(l1, 0, c0)
	l2, c2 = bits.Add64(l2, 0, c1)
	l3, c3 = bits.Add64(l3, l7<<32, c2)
	l4, c4 = bits.Add64(l4, 0, c3)
	l5, c5 = bits.Add64(l5, 0, c4)
	l6, l7 = bits.Add64(l6, 0, c5)

	words[0], c0 = bits.Add64(l0, l7, 0)
	words[1], c1 = bits.Add64(l1, 0, c0)
	words[2], c2 = bits.Add64(l2, 0, c1)
	words[3], c3 = bits.Add64(l3, l7<<32, c2)
	words[4], c4 = bits.Add64(l4, 0, c3)
	words[5], c5 = bits.Add64(l5, 0, c4)
	words[6], _ = bits.Add64(l6, 0, c5)

	for i := range words {
		binary.LittleEndian.PutUint64(z[i*limbBytes:(i+1)*limbBytes], words[i])
	}
}

func toAffine(out *[Size]byte, x, z *fieldElement) {
	inv(z, z)
	mul(x, x, z)
	toBytes(out[:], x)
}

// LowOrderPoint reports whether the provided public key is a low-order point on
// the curve or its twist. This mirrors the validation performed in CIRCL.
func LowOrderPoint(pub *[Size]byte) bool {
	candidates := [...]fieldElement{
		{},
		{1},
		modulus,
	}
	var element fieldElement
	copy(element[:], pub[:])
	modp(&element)
	var match int
	for i := range candidates {
		match |= subtle.ConstantTimeCompare(candidates[i][:], element[:])
	}
	return match != 0
}
