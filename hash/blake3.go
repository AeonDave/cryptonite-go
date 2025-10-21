package hash

import (
	"encoding/binary"
	"errors"
	stdhash "hash"
)

const (
	blake3OutLen   = 32
	blake3KeyLen   = 32
	blake3BlockLen = 64
	blake3ChunkLen = 1024
)

const (
	blake3FlagChunkStart = 1 << 0
	blake3FlagChunkEnd   = 1 << 1
	blake3FlagParent     = 1 << 2
	blake3FlagRoot       = 1 << 3
	blake3FlagKeyedHash  = 1 << 4
)

var blake3IV = [8]uint32{0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19}

var blake3MsgPermutation = [16]int{2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8}

type blake3State struct {
	chunk    chunkState
	key      [8]uint32
	stack    [54][8]uint32
	stackLen int
	flags    uint32
}

type chunkState struct {
	chainingValue    [8]uint32
	chunkCounter     uint64
	block            [blake3BlockLen]byte
	blockLen         uint32
	blocksCompressed uint32
	flags            uint32
}

type blake3Output struct {
	inputCV    [8]uint32
	blockWords [16]uint32
	counter    uint64
	blockLen   uint32
	flags      uint32
}

type blake3Hash struct {
	state *blake3State
	size  int
}

type blake3HasherAdapter struct {
	key   [8]uint32
	flags uint32
}

// NewBLAKE3 returns an unkeyed BLAKE3 hash.Hash producing 32-byte digests.
func NewBLAKE3() stdhash.Hash {
	return newBlake3Hash(blake3IV, 0, blake3OutLen)
}

// NewBLAKE3Keyed returns a keyed BLAKE3 hash.Hash. The key must be exactly 32 bytes.
func NewBLAKE3Keyed(key []byte) (stdhash.Hash, error) {
	if len(key) != blake3KeyLen {
		return nil, errors.New("hash: invalid BLAKE3 key length")
	}
	var words [8]uint32
	loadWords(key, words[:])
	return newBlake3Hash(words, blake3FlagKeyedHash, blake3OutLen), nil
}

// NewBLAKE3Hasher returns a stateless helper implementing hash.Hasher.
func NewBLAKE3Hasher() Hasher {
	return blake3HasherAdapter{key: blake3IV, flags: 0}
}

// NewBLAKE3KeyedHasher returns a keyed helper implementing hash.Hasher.
func NewBLAKE3KeyedHasher(key []byte) (Hasher, error) {
	if len(key) != blake3KeyLen {
		return nil, errors.New("hash: invalid BLAKE3 key length")
	}
	var words [8]uint32
	loadWords(key, words[:])
	return blake3HasherAdapter{key: words, flags: blake3FlagKeyedHash}, nil
}

// SumBLAKE3 computes the 32-byte BLAKE3 digest of msg in a single shot.
func SumBLAKE3(msg []byte) []byte {
	h := NewBLAKE3()
	_, _ = h.Write(msg)
	return h.Sum(nil)
}

func newBlake3Hash(key [8]uint32, flags uint32, size int) stdhash.Hash {
	st := newBlake3State(key, flags)
	return &blake3Hash{state: st, size: size}
}

func newBlake3State(key [8]uint32, flags uint32) *blake3State {
	st := &blake3State{key: key, flags: flags}
	st.chunk = newChunkState(key, 0, flags)
	return st
}

func newChunkState(key [8]uint32, counter uint64, flags uint32) chunkState {
	return chunkState{chainingValue: key, chunkCounter: counter, flags: flags}
}

func (h *blake3Hash) Write(p []byte) (int, error) {
	h.state.update(p)
	return len(p), nil
}

func (h *blake3Hash) Sum(b []byte) []byte {
	out := make([]byte, h.size)
	h.state.finalize(out)
	return append(b, out...)
}

func (h *blake3Hash) Reset() {
	h.state = newBlake3State(h.state.key, h.state.flags)
}

func (h *blake3Hash) Size() int { return h.size }

func (h *blake3Hash) BlockSize() int { return blake3BlockLen }

func (a blake3HasherAdapter) Hash(msg []byte) []byte {
	st := newBlake3State(a.key, a.flags)
	st.update(msg)
	out := make([]byte, blake3OutLen)
	st.finalize(out)
	return out
}

func (a blake3HasherAdapter) Size() int { return blake3OutLen }

func (s *blake3State) update(input []byte) {
	for len(input) > 0 {
		if s.chunk.len() == blake3ChunkLen {
			cv := s.chunk.output().chainingValue()
			total := s.chunk.chunkCounter + 1
			s.addChunkCV(cv, total)
			s.chunk = newChunkState(s.key, total, s.flags)
		}
		want := blake3ChunkLen - s.chunk.len()
		if want > len(input) {
			want = len(input)
		}
		s.chunk.update(input[:want])
		input = input[want:]
	}
}

func (s *blake3State) finalize(out []byte) {
	output := s.chunk.output()
	remaining := s.stackLen
	for remaining > 0 {
		remaining--
		output = parentOutput(s.stack[remaining], output.chainingValue(), s.key, s.flags)
	}
	output.rootOutputBytes(out)
}

func (s *blake3State) addChunkCV(cv [8]uint32, totalChunks uint64) {
	for totalChunks&1 == 0 {
		totalChunks >>= 1
		cv = parentCV(s.pop(), cv, s.key, s.flags)
	}
	s.push(cv)
}

func (s *blake3State) push(cv [8]uint32) {
	s.stack[s.stackLen] = cv
	s.stackLen++
}

func (s *blake3State) pop() [8]uint32 {
	s.stackLen--
	return s.stack[s.stackLen]
}

func (c *chunkState) len() int {
	return int(c.blocksCompressed)*blake3BlockLen + int(c.blockLen)
}

func (c *chunkState) startFlag() uint32 {
	if c.blocksCompressed == 0 {
		return blake3FlagChunkStart
	}
	return 0
}

func (c *chunkState) update(input []byte) {
	for len(input) > 0 {
		if int(c.blockLen) == blake3BlockLen {
			var words [16]uint32
			loadWords(c.block[:], words[:])
			c.chainingValue = firstEightWords(compress(&c.chainingValue, &words, c.chunkCounter, blake3BlockLen, c.flags|c.startFlag()))
			c.blocksCompressed++
			var zero [blake3BlockLen]byte
			c.block = zero
			c.blockLen = 0
		}
		want := blake3BlockLen - int(c.blockLen)
		if want > len(input) {
			want = len(input)
		}
		copy(c.block[int(c.blockLen):], input[:want])
		c.blockLen += uint32(want)
		input = input[want:]
	}
}

func (c *chunkState) output() blake3Output {
	var words [16]uint32
	loadWords(c.block[:], words[:])
	return blake3Output{
		inputCV:    c.chainingValue,
		blockWords: words,
		counter:    c.chunkCounter,
		blockLen:   c.blockLen,
		flags:      c.flags | c.startFlag() | blake3FlagChunkEnd,
	}
}

func parentOutput(left, right [8]uint32, key [8]uint32, flags uint32) blake3Output {
	var block [16]uint32
	copy(block[:8], left[:])
	copy(block[8:], right[:])
	return blake3Output{
		inputCV:    key,
		blockWords: block,
		counter:    0,
		blockLen:   blake3BlockLen,
		flags:      flags | blake3FlagParent,
	}
}

func parentCV(left, right [8]uint32, key [8]uint32, flags uint32) [8]uint32 {
	return parentOutput(left, right, key, flags).chainingValue()
}

func (o blake3Output) chainingValue() [8]uint32 {
	return firstEightWords(compress(&o.inputCV, &o.blockWords, o.counter, o.blockLen, o.flags))
}

func (o blake3Output) rootOutputBytes(dst []byte) {
	var counter uint64
	for len(dst) > 0 {
		words := compress(&o.inputCV, &o.blockWords, counter, o.blockLen, o.flags|blake3FlagRoot)
		var block [blake3BlockLen]byte
		storeWords(words[:], block[:])
		take := blake3BlockLen
		if take > len(dst) {
			take = len(dst)
		}
		copy(dst, block[:take])
		dst = dst[take:]
		counter++
	}
}

func firstEightWords(words [16]uint32) [8]uint32 {
	var out [8]uint32
	copy(out[:], words[:8])
	return out
}

func compress(cv *[8]uint32, block *[16]uint32, counter uint64, blockLen uint32, flags uint32) [16]uint32 {
	var state [16]uint32
	copy(state[0:8], cv[:])
	state[8] = blake3IV[0]
	state[9] = blake3IV[1]
	state[10] = blake3IV[2]
	state[11] = blake3IV[3]
	state[12] = uint32(counter)
	state[13] = uint32(counter >> 32)
	state[14] = blockLen
	state[15] = flags

	words := *block
	round(&state, &words)
	permute(&words)
	round(&state, &words)
	permute(&words)
	round(&state, &words)
	permute(&words)
	round(&state, &words)
	permute(&words)
	round(&state, &words)
	permute(&words)
	round(&state, &words)
	permute(&words)
	round(&state, &words)

	for i := 0; i < 8; i++ {
		state[i] ^= state[i+8]
		state[i+8] ^= cv[i]
	}
	return state
}

func round(state *[16]uint32, m *[16]uint32) {
	g(state, 0, 4, 8, 12, m[0], m[1])
	g(state, 1, 5, 9, 13, m[2], m[3])
	g(state, 2, 6, 10, 14, m[4], m[5])
	g(state, 3, 7, 11, 15, m[6], m[7])
	g(state, 0, 5, 10, 15, m[8], m[9])
	g(state, 1, 6, 11, 12, m[10], m[11])
	g(state, 2, 7, 8, 13, m[12], m[13])
	g(state, 3, 4, 9, 14, m[14], m[15])
}

func permute(m *[16]uint32) {
	var tmp [16]uint32
	for i := range tmp {
		tmp[i] = m[blake3MsgPermutation[i]]
	}
	*m = tmp
}

func g(state *[16]uint32, a, b, c, d int, mx, my uint32) {
	state[a] = state[a] + state[b] + mx
	state[d] = rotateRight(state[d]^state[a], 16)
	state[c] = state[c] + state[d]
	state[b] = rotateRight(state[b]^state[c], 12)
	state[a] = state[a] + state[b] + my
	state[d] = rotateRight(state[d]^state[a], 8)
	state[c] = state[c] + state[d]
	state[b] = rotateRight(state[b]^state[c], 7)
}

func rotateRight(x uint32, n uint) uint32 { return (x >> n) | (x << (32 - n)) }

func loadWords(src []byte, dst []uint32) {
	for i := 0; i < len(dst); i++ {
		base := 4 * i
		if base+4 <= len(src) {
			dst[i] = binary.LittleEndian.Uint32(src[base : base+4])
			continue
		}
		var buf [4]byte
		copy(buf[:], src[base:])
		dst[i] = binary.LittleEndian.Uint32(buf[:])
	}
}

func storeWords(words []uint32, dst []byte) {
	for i, w := range words {
		base := 4 * i
		if base+4 <= len(dst) {
			binary.LittleEndian.PutUint32(dst[base:base+4], w)
			continue
		}
		var buf [4]byte
		binary.LittleEndian.PutUint32(buf[:], w)
		copy(dst[base:], buf[:])
	}
}
