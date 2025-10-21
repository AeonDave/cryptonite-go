// Portions of this file are adapted from the Oasis Labs Deoxys-II implementation
// (https://github.com/oasisprotocol/deoxysii) which is distributed under the MIT
// license. The relevant license terms are preserved below.
//
// Copyright (c) 2019 Oasis Labs Inc. <info@oasislabs.com>
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
// BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
// ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package deoxysii

var rcons = [stkCount]byte{
	0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a,
	0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
	0x72,
}

func applyH(t *[stkSize]byte) {
	t[0], t[1], t[2], t[3], t[4], t[5], t[6], t[7],
		t[8], t[9], t[10], t[11], t[12], t[13], t[14], t[15] =
		t[1], t[6], t[11], t[12], t[5], t[10], t[15], t[0],
		t[9], t[14], t[3], t[4], t[13], t[2], t[7], t[8]
}

func lfsr2(t *[stkSize]byte) {
	for i, x := range t {
		// x7 || x6 || x5 || x4 || x3 || x2 || x1 || x0 ->
		// x6 || x5 || x4 || x3 || x2 || x1 || x0 || x7 ^ x5
		x7, x5 := x>>7, (x>>5)&1
		t[i] = (x << 1) | (x7 ^ x5)
	}
}

func lfsr3(t *[stkSize]byte) {
	for i, x := range t {
		// x7 || x6 || x5 || x4 || x3 || x2 || x1 || x0 ->
		// x0 ^ x6 || x7 || x6 || x5 || x4 || x3 || x2 || x1
		x0, x6 := x&1, (x>>6)&1
		t[i] = (x >> 1) | ((x0 ^ x6) << 7)
	}
}

func xorRC(t *[stkSize]byte, i int) {
	rc := [stkSize]byte{
		1, 2, 4, 8,
		rcons[i], rcons[i], rcons[i], rcons[i],
		0, 0, 0, 0,
		0, 0, 0, 0,
	}
	xorBytes(t[:], t[:], rc[:], 8)
}

func deriveK(key []byte) ([rounds + 1][stkSize]byte, error) {
	if len(key) != KeySize {
		return [rounds + 1][stkSize]byte{}, errInvalidKeySize
	}
	var (
		derived [rounds + 1][stkSize]byte
		tk2     [stkSize]byte
		tk3     [stkSize]byte
	)
	copy(tk2[:], key[16:32])
	copy(tk3[:], key[0:16])

	xorBytes(derived[0][:], tk2[:], tk3[:], stkSize)
	xorRC(&derived[0], 0)

	for i := 1; i <= rounds; i++ {
		lfsr2(&tk2)
		applyH(&tk2)

		lfsr3(&tk3)
		applyH(&tk3)

		xorBytes(derived[i][:], tk2[:], tk3[:], stkSize)
		xorRC(&derived[i], i)
	}
	return derived, nil
}
