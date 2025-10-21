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

import "encoding/binary"

const (
	rounds    = 16
	tweakSize = 16

	stkSize  = 16
	stkCount = rounds + 1

	prefixADBlock  = 0x2
	prefixADFinal  = 0x6
	prefixMsgBlock = 0x0
	prefixMsgFinal = 0x4
	prefixTag      = 0x1

	prefixShift = 4
)

func xorBytes(out, a, b []byte, n int) {
	for i := 0; i < n; i++ {
		out[i] = a[i] ^ b[i]
	}
}

func encodeTagTweak(out *[tweakSize]byte, prefix byte, blockNr int) {
	binary.BigEndian.PutUint64(out[8:], uint64(blockNr))
	out[0] = prefix << prefixShift
}

func encodeEncTweak(out *[tweakSize]byte, tag []byte, blockNr int) {
	var tmp [8]byte
	binary.BigEndian.PutUint64(tmp[:], uint64(blockNr))
	copy(out[:], tag[:])
	out[0] |= 0x80
	xorBytes(out[8:], out[8:], tmp[:], 8)
}
