package keccak

import "encoding/binary"

// LeftEncode encodes the input integer x following the SP 800-185 definition.
func LeftEncode(x uint64) []byte {
	var tmp [9]byte
	binary.BigEndian.PutUint64(tmp[1:], x)
	i := 1
	for i < len(tmp)-1 && tmp[i] == 0 {
		i++
	}
	bytes := tmp[i:]
	if len(bytes) == 0 {
		bytes = []byte{0}
	}
	out := make([]byte, len(bytes)+1)
	out[0] = byte(len(bytes))
	copy(out[1:], bytes)
	return out
}

// RightEncode encodes the input integer x following the SP 800-185 definition.
func RightEncode(x uint64) []byte {
	var tmp [9]byte
	binary.BigEndian.PutUint64(tmp[1:], x)
	i := 1
	for i < len(tmp)-1 && tmp[i] == 0 {
		i++
	}
	bytes := tmp[i:]
	if len(bytes) == 0 {
		bytes = []byte{0}
	}
	out := make([]byte, len(bytes)+1)
	copy(out, bytes)
	out[len(bytes)] = byte(len(bytes))
	return out
}

// EncodeString encodes a byte string per SP 800-185.
func EncodeString(data []byte) []byte {
	encoded := LeftEncode(uint64(len(data) * 8))
	encoded = append(encoded, data...)
	return encoded
}

// Bytepad applies the SP 800-185 bytepad operation to the input.
func Bytepad(x []byte, w int) []byte {
	if w <= 0 {
		return append([]byte(nil), x...)
	}
	out := LeftEncode(uint64(w))
	out = append(out, x...)
	remainder := len(out) % w
	if remainder != 0 {
		padLen := w - remainder
		out = append(out, make([]byte, padLen)...)
	}
	return out
}
