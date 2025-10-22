package keccak

import "errors"

const domainCSHAKE = 0x04

// TupleHash128 computes the TupleHash-128 digest over the provided tuple, using
// the optional customization string. The output length is measured in bytes.
func TupleHash128(tuple [][]byte, customization []byte, outLen int) ([]byte, error) {
	if outLen <= 0 {
		return nil, errors.New("keccak: invalid TupleHash128 output length")
	}
	x := newParametrisedXOF(168, []byte(tupleHashFn), customization)
	return tupleHash(x, tuple, outLen)
}

// TupleHash256 computes the TupleHash-256 digest over the provided tuple.
func TupleHash256(tuple [][]byte, customization []byte, outLen int) ([]byte, error) {
	if outLen <= 0 {
		return nil, errors.New("keccak: invalid TupleHash256 output length")
	}
	x := newParametrisedXOF(136, []byte(tupleHashFn), customization)
	return tupleHash(x, tuple, outLen)
}

func tupleHash(x *paramXOF, tuple [][]byte, outLen int) ([]byte, error) {
	for _, element := range tuple {
		x.Write(EncodeString(element))
	}
	x.Write(RightEncode(uint64(outLen * 8)))
	out := make([]byte, outLen)
	x.Read(out)
	return out, nil
}

// ParallelHash128 computes ParallelHash-128 over msg using the given blockSize
// and customization, producing outLen bytes of output.
func ParallelHash128(msg []byte, blockSize int, customization []byte, outLen int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, errors.New("keccak: invalid block size for ParallelHash128")
	}
	if outLen <= 0 {
		return nil, errors.New("keccak: invalid ParallelHash128 output length")
	}
	return parallelHash(168, 32, msg, blockSize, customization, outLen)
}

// ParallelHash256 computes ParallelHash-256 over msg using the given blockSize
// and customization.
func ParallelHash256(msg []byte, blockSize int, customization []byte, outLen int) ([]byte, error) {
	if blockSize <= 0 {
		return nil, errors.New("keccak: invalid block size for ParallelHash256")
	}
	if outLen <= 0 {
		return nil, errors.New("keccak: invalid ParallelHash256 output length")
	}
	return parallelHash(136, 64, msg, blockSize, customization, outLen)
}

func parallelHash(rate, digestLen int, msg []byte, blockSize int, customization []byte, outLen int) ([]byte, error) {
	blocks := splitBlocks(msg, blockSize)
	if len(blocks) == 0 {
		blocks = append(blocks, []byte{})
	}
	intermediates := make([][]byte, 0, len(blocks))
	for _, block := range blocks {
		inner := newParametrisedXOF(rate, []byte(parallelHashFn), customization)
		inner.Write(EncodeString(block))
		inner.Write(RightEncode(uint64(blockSize * 8)))
		buf := make([]byte, digestLen)
		inner.Read(buf)
		intermediates = append(intermediates, buf)
	}
	outer := newParametrisedXOF(rate, []byte(parallelHashFn), customization)
	for _, elem := range intermediates {
		outer.Write(EncodeString(elem))
	}
	outer.Write(RightEncode(uint64(len(intermediates))))
	outer.Write(RightEncode(uint64(outLen * 8)))
	out := make([]byte, outLen)
	outer.Read(out)
	return out, nil
}

func splitBlocks(msg []byte, blockSize int) [][]byte {
	if blockSize <= 0 || len(msg) == 0 {
		return nil
	}
	n := (len(msg) + blockSize - 1) / blockSize
	blocks := make([][]byte, 0, n)
	for i := 0; i < n; i++ {
		start := i * blockSize
		end := start + blockSize
		if end > len(msg) {
			end = len(msg)
		}
		dup := make([]byte, end-start)
		copy(dup, msg[start:end])
		blocks = append(blocks, dup)
	}
	return blocks
}

type paramXOF struct {
	sponge        Sponge
	rate          int
	functionName  []byte
	customization []byte
}

func newParametrisedXOF(rate int, functionName, customization []byte) *paramXOF {
	p := &paramXOF{
		rate:          rate,
		functionName:  append([]byte(nil), functionName...),
		customization: append([]byte(nil), customization...),
	}
	p.reset()
	return p
}

func (p *paramXOF) reset() {
	p.sponge.Init(p.rate, domainCSHAKE)
	if len(p.functionName) != 0 || len(p.customization) != 0 {
		prefix := EncodeString(p.functionName)
		prefix = append(prefix, EncodeString(p.customization)...)
		prefixed := Bytepad(prefix, p.rate)
		p.sponge.Absorb(prefixed)
	}
}

func (p *paramXOF) Write(data []byte) {
	p.sponge.Absorb(data)
}

func (p *paramXOF) Read(out []byte) {
	p.sponge.Squeeze(out)
}

const (
	tupleHashFn    = "TupleHash"
	parallelHashFn = "ParallelHash"
)
