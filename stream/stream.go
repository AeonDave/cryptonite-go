package stream

// Stream represents a synchronous stream cipher that can either generate raw
// keystream bytes or XOR them with input in place.
type Stream interface {
	// KeyStream writes len(dst) keystream bytes into dst.
	KeyStream(dst []byte)
	// XORKeyStream XORs the keystream with src, writing the result to dst.
	// The src and dst slices may overlap.
	XORKeyStream(dst, src []byte)
	// Reset rewinds the stream to the supplied block counter.
	Reset(counter uint32)
}
