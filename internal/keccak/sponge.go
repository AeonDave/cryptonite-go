package keccak

import "encoding/binary"

const MaxRate = 168

type Sponge struct {
	state     [25]uint64
	buf       [MaxRate]byte
	rate      int
	off       int
	ds        byte
	squeezing bool
}

func (s *Sponge) Init(rate int, ds byte) {
	s.rate = rate
	s.ds = ds
	s.Reset()
}

func (s *Sponge) Reset() {
	for i := range s.state {
		s.state[i] = 0
	}
	for i := 0; i < s.rate; i++ {
		s.buf[i] = 0
	}
	s.off = 0
	s.squeezing = false
}

func (s *Sponge) Absorb(p []byte) {
	if s.squeezing {
		s.Reset()
	}
	for len(p) > 0 {
		n := copy(s.buf[s.off:s.rate], p)
		s.off += n
		p = p[n:]
		if s.off == s.rate {
			s.absorbBlock()
		}
	}
}

func (s *Sponge) absorbBlock() {
	xorIn(&s.state, s.buf[:s.rate])
	for i := 0; i < s.rate; i++ {
		s.buf[i] = 0
	}
	keccakF1600(&s.state)
	s.off = 0
}

func (s *Sponge) finalize() {
	if s.squeezing {
		return
	}
	if s.off == s.rate {
		s.absorbBlock()
	}
	buf := s.buf[:s.rate]
	buf[s.off] ^= s.ds
	buf[s.rate-1] ^= 0x80
	xorIn(&s.state, buf)
	for i := 0; i < s.rate; i++ {
		buf[i] = 0
	}
	keccakF1600(&s.state)
	s.off = 0
	s.squeezing = true
}

func (s *Sponge) Squeeze(out []byte) {
	if len(out) == 0 {
		return
	}
	s.finalize()
	produced := 0
	for produced < len(out) {
		if s.off == 0 {
			extract(&s.state, s.buf[:s.rate])
		}
		n := copy(out[produced:], s.buf[s.off:s.rate])
		produced += n
		s.off += n
		if s.off == s.rate {
			keccakF1600(&s.state)
			s.off = 0
		}
	}
}

func (s *Sponge) Rate() int { return s.rate }

func xorIn(state *[25]uint64, buf []byte) {
	for i := 0; i < len(buf)/8; i++ {
		state[i] ^= binary.LittleEndian.Uint64(buf[i*8:])
	}
}

func extract(state *[25]uint64, buf []byte) {
	for i := 0; i < len(buf)/8; i++ {
		binary.LittleEndian.PutUint64(buf[i*8:], state[i])
	}
}

// SumFixed absorbs msg into a fresh Keccak sponge with the provided
// parameters and squeezes a fixed-length digest into out. The domain
// separation byte must follow the conventions from NIST FIPS 202.
func SumFixed(rate int, ds byte, out, msg []byte) {
	var s Sponge
	s.Init(rate, ds)
	s.Absorb(msg)
	s.Squeeze(out)
}
