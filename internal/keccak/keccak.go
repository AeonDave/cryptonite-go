package keccak

import "math/bits"

var roundConstants = [24]uint64{
	0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
	0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
	0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
	0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
	0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
	0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
}

var rotationOffsets = [5][5]uint{
	{0, 36, 3, 41, 18},
	{1, 44, 10, 45, 2},
	{62, 6, 43, 15, 61},
	{28, 55, 25, 21, 56},
	{27, 20, 39, 8, 14},
}

// keccakF1600 applies the Keccak-f[1600] permutation in-place on the state.
func keccakF1600(a *[25]uint64) {
	for round := 0; round < 24; round++ {
		var c [5]uint64
		for x := 0; x < 5; x++ {
			c[x] = a[x] ^ a[x+5] ^ a[x+10] ^ a[x+15] ^ a[x+20]
		}

		var d [5]uint64
		for x := 0; x < 5; x++ {
			d[x] = c[(x+4)%5] ^ bits.RotateLeft64(c[(x+1)%5], 1)
		}

		for y := 0; y < 5; y++ {
			base := 5 * y
			for x := 0; x < 5; x++ {
				a[base+x] ^= d[x]
			}
		}

		var b [5][5]uint64
		for x := 0; x < 5; x++ {
			for y := 0; y < 5; y++ {
				rotated := bits.RotateLeft64(a[x+5*y], int(rotationOffsets[x][y]))
				newX := y
				newY := (2*x + 3*y) % 5
				b[newX][newY] = rotated
			}
		}

		for y := 0; y < 5; y++ {
			for x := 0; x < 5; x++ {
				a[x+5*y] = b[x][y] ^ ((^b[(x+1)%5][y]) & b[(x+2)%5][y])
			}
		}

		a[0] ^= roundConstants[round]
	}
}
