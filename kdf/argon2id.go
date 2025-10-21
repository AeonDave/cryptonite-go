package kdf

// The implementation in this file is adapted from Go's golang.org/x/crypto/argon2
// package (BSD-style license). It has been pared down to the Argon2id variant
// and rewritten to avoid external dependencies while retaining RFC 9106
// compliance.

import (
	"encoding/binary"
	"errors"
	"hash"
	"math"

	"github.com/AeonDave/cryptonite-go/internal/blake2b"
)

const (
	argon2idVersion    = 0x13
	argon2SyncPoints   = 4
	argon2BlockLength  = 128 // block length in uint64 words (1 KiB)
	argon2MinSaltBytes = 8

	argon2ModeID = 2
)

// Argon2idDeriver implements the Deriver interface for Argon2id.
type Argon2idDeriver struct {
	MemoryKiB uint32 // total memory in KiB (default 64 MiB)
	Time      uint32 // number of passes (default 1)
	Threads   uint32 // lanes/parallelism (default 1)
}

// NewArgon2id returns a Deriver configured with RFC 9106's interactive defaults
// (time=1, memory=64 MiB, threads=1).
func NewArgon2id() Deriver {
	return Argon2idDeriver{
		MemoryKiB: 64 * 1024,
		Time:      1,
		Threads:   1,
	}
}

// NewArgon2idWithParams allows callers to customise the Argon2id cost factors.
// Memory is expressed in KiB; threads controls the number of lanes processed.
func NewArgon2idWithParams(time, memoryKiB, threads uint32) Deriver {
	return Argon2idDeriver{
		MemoryKiB: memoryKiB,
		Time:      time,
		Threads:   threads,
	}
}

// Argon2id is a single-shot helper mirroring Argon2idDeriver.
func Argon2id(secret, salt []byte, time, memoryKiB, threads uint32, length int) ([]byte, error) {
	d := Argon2idDeriver{
		MemoryKiB: memoryKiB,
		Time:      time,
		Threads:   threads,
	}
	return d.Derive(DeriveParams{
		Secret: secret,
		Salt:   salt,
		Length: length,
	})
}

// Derive implements Deriver for Argon2id.
func (a Argon2idDeriver) Derive(params DeriveParams) ([]byte, error) {
	if len(params.Secret) == 0 {
		return nil, errors.New("kdf: argon2id secret must be non-empty")
	}
	if len(params.Salt) < argon2MinSaltBytes {
		return nil, errors.New("kdf: argon2id salt must be at least 8 bytes")
	}
	if params.Length <= 0 {
		return nil, errors.New("kdf: argon2id output length must be positive")
	}
	if params.Length > int(math.MaxUint32) {
		return nil, errors.New("kdf: argon2id output length too large")
	}

	time := a.Time
	if time == 0 {
		time = 1
	}
	memory := a.MemoryKiB
	if memory == 0 {
		memory = 64 * 1024
	}
	threads := a.Threads
	if threads == 0 {
		threads = 1
	}

	return argon2idKey(params.Secret, params.Salt, time, memory, threads, uint32(params.Length))
}

type argon2Block [argon2BlockLength]uint64

func argon2idKey(password, salt []byte, time, memoryKiB, threads, keyLen uint32) ([]byte, error) {
	if keyLen == 0 {
		return nil, errors.New("kdf: argon2id output length must be positive")
	}
	if len(password) > math.MaxUint32 {
		return nil, errors.New("kdf: argon2id password too long")
	}
	if len(salt) > math.MaxUint32 {
		return nil, errors.New("kdf: argon2id salt too long")
	}
	if threads == 0 {
		return nil, errors.New("kdf: argon2id requires at least one lane")
	}
	if time == 0 {
		return nil, errors.New("kdf: argon2id requires at least one iteration")
	}

	unit := argon2SyncPoints * threads
	if memoryKiB < 2*unit {
		memoryKiB = 2 * unit
	}
	// Round memory down to a multiple of lanes*syncPoints to guarantee full segments.
	memoryKiB = (memoryKiB / unit) * unit
	if memoryKiB < 2*unit {
		memoryKiB = 2 * unit
	}

	h0 := initArgon2Hash(password, salt, nil, nil, time, memoryKiB, threads, keyLen, argon2ModeID)
	blocks := initArgon2Blocks(&h0, memoryKiB, threads)
	processArgon2Blocks(blocks, time, memoryKiB, threads, argon2ModeID)
	return extractArgon2Key(blocks, memoryKiB, threads, keyLen), nil
}

func initArgon2Hash(password, salt, key, data []byte, time, memoryKiB, threads, keyLen uint32, mode int) [blake2b.Size + 8]byte {
	var (
		h0     [blake2b.Size + 8]byte
		params [24]byte
		tmp    [4]byte
	)

	digest, err := blake2b.New512(nil)
	if err != nil {
		panic("argon2id: failed to initialise blake2b-512")
	}
	binary.LittleEndian.PutUint32(params[0:4], threads)
	binary.LittleEndian.PutUint32(params[4:8], keyLen)
	binary.LittleEndian.PutUint32(params[8:12], memoryKiB)
	binary.LittleEndian.PutUint32(params[12:16], time)
	binary.LittleEndian.PutUint32(params[16:20], argon2idVersion)
	binary.LittleEndian.PutUint32(params[20:24], uint32(mode))
	digest.Write(params[:])

	binary.LittleEndian.PutUint32(tmp[:], uint32(len(password)))
	digest.Write(tmp[:])
	digest.Write(password)

	binary.LittleEndian.PutUint32(tmp[:], uint32(len(salt)))
	digest.Write(tmp[:])
	digest.Write(salt)

	binary.LittleEndian.PutUint32(tmp[:], uint32(len(key)))
	digest.Write(tmp[:])
	digest.Write(key)

	binary.LittleEndian.PutUint32(tmp[:], uint32(len(data)))
	digest.Write(tmp[:])
	digest.Write(data)

	digest.Sum(h0[:0])
	return h0
}

func initArgon2Blocks(h0 *[blake2b.Size + 8]byte, memoryKiB, threads uint32) []argon2Block {
	var tmp [1024]byte
	B := make([]argon2Block, memoryKiB)
	lanes := memoryKiB / threads

	for lane := uint32(0); lane < threads; lane++ {
		first := lane * lanes
		binary.LittleEndian.PutUint32(h0[blake2b.Size+4:], lane)

		binary.LittleEndian.PutUint32(h0[blake2b.Size:], 0)
		blake2bHash(tmp[:], h0[:])
		for i := range B[first] {
			B[first][i] = binary.LittleEndian.Uint64(tmp[i*8:])
		}

		binary.LittleEndian.PutUint32(h0[blake2b.Size:], 1)
		blake2bHash(tmp[:], h0[:])
		for i := range B[first+1] {
			B[first+1][i] = binary.LittleEndian.Uint64(tmp[i*8:])
		}
	}
	return B
}

func processArgon2Blocks(B []argon2Block, time, memoryKiB, threads uint32, mode int) {
	lanes := memoryKiB / threads
	segmentLength := lanes / argon2SyncPoints

	for pass := uint32(0); pass < time; pass++ {
		for slice := uint32(0); slice < argon2SyncPoints; slice++ {
			for lane := uint32(0); lane < threads; lane++ {
				processArgon2Segment(B, pass, slice, lane, time, memoryKiB, threads, mode, lanes, segmentLength)
			}
		}
	}
}

func processArgon2Segment(B []argon2Block, pass, slice, lane, time, memoryKiB, threads uint32, mode int, lanes, segmentLength uint32) {
	var (
		addresses argon2Block
		input     argon2Block
		zero      argon2Block
	)

	if mode == argon2ModeID && pass == 0 && slice < argon2SyncPoints/2 {
		input[0] = uint64(pass)
		input[1] = uint64(lane)
		input[2] = uint64(slice)
		input[3] = uint64(memoryKiB)
		input[4] = uint64(time)
		input[5] = uint64(mode)
	}

	index := uint32(0)
	if pass == 0 && slice == 0 {
		index = 2 // first two blocks already generated
		if mode == argon2ModeID {
			input[6]++
			processBlock(&addresses, &input, &zero)
			processBlock(&addresses, &addresses, &zero)
		}
	}

	offset := lane*lanes + slice*segmentLength + index
	for ; index < segmentLength; index, offset = index+1, offset+1 {
		prev := offset - 1
		if index == 0 && slice == 0 {
			prev += lanes
		}

		var random uint64
		if mode == argon2ModeID && pass == 0 && slice < argon2SyncPoints/2 {
			if index%argon2BlockLength == 0 {
				input[6]++
				processBlock(&addresses, &input, &zero)
				processBlock(&addresses, &addresses, &zero)
			}
			random = addresses[index%argon2BlockLength]
		} else {
			random = B[prev][0]
		}

		refIndex := indexAlpha(random, lanes, segmentLength, threads, pass, slice, lane, index)
		processBlockXOR(&B[offset], &B[prev], &B[refIndex])
	}
}

func extractArgon2Key(B []argon2Block, memoryKiB, threads, keyLen uint32) []byte {
	lanes := memoryKiB / threads
	lastLaneIndex := memoryKiB - 1

	for lane := uint32(0); lane < threads-1; lane++ {
		lastBlock := (lane * lanes) + (lanes - 1)
		for i, v := range B[lastBlock] {
			B[lastLaneIndex][i] ^= v
		}
	}

	var blockBytes [1024]byte
	for i, v := range B[lastLaneIndex] {
		binary.LittleEndian.PutUint64(blockBytes[i*8:], v)
	}

	out := make([]byte, keyLen)
	blake2bHash(out, blockBytes[:])
	return out
}

func indexAlpha(rand uint64, lanes, segmentLength, threads, pass, slice, lane, index uint32) uint32 {
	refLane := uint32(rand>>32) % threads
	if pass == 0 && slice == 0 {
		refLane = lane
	}
	m, s := 3*segmentLength, ((slice+1)%argon2SyncPoints)*segmentLength
	if lane == refLane {
		m += index
	}
	if pass == 0 {
		m, s = slice*segmentLength, 0
		if slice == 0 || lane == refLane {
			m += index
		}
	}
	if index == 0 || lane == refLane {
		m--
	}
	return phi(rand, uint64(m), uint64(s), refLane, lanes)
}

func phi(rand, m, s uint64, lane, lanes uint32) uint32 {
	p := rand & 0xFFFFFFFF
	p = (p * p) >> 32
	p = (p * m) >> 32
	return lane*lanes + uint32((s+m-(p+1))%uint64(lanes))
}

func processBlock(out, in1, in2 *argon2Block) {
	processBlockGeneric(out, in1, in2, false)
}

func processBlockXOR(out, in1, in2 *argon2Block) {
	processBlockGeneric(out, in1, in2, true)
}

func processBlockGeneric(out, in1, in2 *argon2Block, xor bool) {
	var t argon2Block
	for i := range t {
		t[i] = in1[i] ^ in2[i]
	}
	for i := 0; i < argon2BlockLength; i += 16 {
		blamka(
			&t[i+0], &t[i+1], &t[i+2], &t[i+3],
			&t[i+4], &t[i+5], &t[i+6], &t[i+7],
			&t[i+8], &t[i+9], &t[i+10], &t[i+11],
			&t[i+12], &t[i+13], &t[i+14], &t[i+15],
		)
	}
	for i := 0; i < argon2BlockLength/8; i += 2 {
		blamka(
			&t[i], &t[i+1], &t[16+i], &t[16+i+1],
			&t[32+i], &t[32+i+1], &t[48+i], &t[48+i+1],
			&t[64+i], &t[64+i+1], &t[80+i], &t[80+i+1],
			&t[96+i], &t[96+i+1], &t[112+i], &t[112+i+1],
		)
	}
	if xor {
		for i := range t {
			out[i] ^= in1[i] ^ in2[i] ^ t[i]
		}
	} else {
		for i := range t {
			out[i] = in1[i] ^ in2[i] ^ t[i]
		}
	}
}

func blamka(t00, t01, t02, t03, t04, t05, t06, t07, t08, t09, t10, t11, t12, t13, t14, t15 *uint64) {
	v00, v01, v02, v03 := *t00, *t01, *t02, *t03
	v04, v05, v06, v07 := *t04, *t05, *t06, *t07
	v08, v09, v10, v11 := *t08, *t09, *t10, *t11
	v12, v13, v14, v15 := *t12, *t13, *t14, *t15

	v00 += v04 + 2*uint64(uint32(v00))*uint64(uint32(v04))
	v12 ^= v00
	v12 = v12>>32 | v12<<32
	v08 += v12 + 2*uint64(uint32(v08))*uint64(uint32(v12))
	v04 ^= v08
	v04 = v04>>24 | v04<<40

	v00 += v04 + 2*uint64(uint32(v00))*uint64(uint32(v04))
	v12 ^= v00
	v12 = v12>>16 | v12<<48
	v08 += v12 + 2*uint64(uint32(v08))*uint64(uint32(v12))
	v04 ^= v08
	v04 = v04>>63 | v04<<1

	v01 += v05 + 2*uint64(uint32(v01))*uint64(uint32(v05))
	v13 ^= v01
	v13 = v13>>32 | v13<<32
	v09 += v13 + 2*uint64(uint32(v09))*uint64(uint32(v13))
	v05 ^= v09
	v05 = v05>>24 | v05<<40

	v01 += v05 + 2*uint64(uint32(v01))*uint64(uint32(v05))
	v13 ^= v01
	v13 = v13>>16 | v13<<48
	v09 += v13 + 2*uint64(uint32(v09))*uint64(uint32(v13))
	v05 ^= v09
	v05 = v05>>63 | v05<<1

	v02 += v06 + 2*uint64(uint32(v02))*uint64(uint32(v06))
	v14 ^= v02
	v14 = v14>>32 | v14<<32
	v10 += v14 + 2*uint64(uint32(v10))*uint64(uint32(v14))
	v06 ^= v10
	v06 = v06>>24 | v06<<40

	v02 += v06 + 2*uint64(uint32(v02))*uint64(uint32(v06))
	v14 ^= v02
	v14 = v14>>16 | v14<<48
	v10 += v14 + 2*uint64(uint32(v10))*uint64(uint32(v14))
	v06 ^= v10
	v06 = v06>>63 | v06<<1

	v03 += v07 + 2*uint64(uint32(v03))*uint64(uint32(v07))
	v15 ^= v03
	v15 = v15>>32 | v15<<32
	v11 += v15 + 2*uint64(uint32(v11))*uint64(uint32(v15))
	v07 ^= v11
	v07 = v07>>24 | v07<<40

	v03 += v07 + 2*uint64(uint32(v03))*uint64(uint32(v07))
	v15 ^= v03
	v15 = v15>>16 | v15<<48
	v11 += v15 + 2*uint64(uint32(v11))*uint64(uint32(v15))
	v07 ^= v11
	v07 = v07>>63 | v07<<1

	v00 += v05 + 2*uint64(uint32(v00))*uint64(uint32(v05))
	v15 ^= v00
	v15 = v15>>32 | v15<<32
	v10 += v15 + 2*uint64(uint32(v10))*uint64(uint32(v15))
	v05 ^= v10
	v05 = v05>>24 | v05<<40

	v00 += v05 + 2*uint64(uint32(v00))*uint64(uint32(v05))
	v15 ^= v00
	v15 = v15>>16 | v15<<48
	v10 += v15 + 2*uint64(uint32(v10))*uint64(uint32(v15))
	v05 ^= v10
	v05 = v05>>63 | v05<<1

	v01 += v06 + 2*uint64(uint32(v01))*uint64(uint32(v06))
	v12 ^= v01
	v12 = v12>>32 | v12<<32
	v11 += v12 + 2*uint64(uint32(v11))*uint64(uint32(v12))
	v06 ^= v11
	v06 = v06>>24 | v06<<40

	v01 += v06 + 2*uint64(uint32(v01))*uint64(uint32(v06))
	v12 ^= v01
	v12 = v12>>16 | v12<<48
	v11 += v12 + 2*uint64(uint32(v11))*uint64(uint32(v12))
	v06 ^= v11
	v06 = v06>>63 | v06<<1

	v02 += v07 + 2*uint64(uint32(v02))*uint64(uint32(v07))
	v13 ^= v02
	v13 = v13>>32 | v13<<32
	v08 += v13 + 2*uint64(uint32(v08))*uint64(uint32(v13))
	v07 ^= v08
	v07 = v07>>24 | v07<<40

	v02 += v07 + 2*uint64(uint32(v02))*uint64(uint32(v07))
	v13 ^= v02
	v13 = v13>>16 | v13<<48
	v08 += v13 + 2*uint64(uint32(v08))*uint64(uint32(v13))
	v07 ^= v08
	v07 = v07>>63 | v07<<1

	v03 += v04 + 2*uint64(uint32(v03))*uint64(uint32(v04))
	v14 ^= v03
	v14 = v14>>32 | v14<<32
	v09 += v14 + 2*uint64(uint32(v09))*uint64(uint32(v14))
	v04 ^= v09
	v04 = v04>>24 | v04<<40

	v03 += v04 + 2*uint64(uint32(v03))*uint64(uint32(v04))
	v14 ^= v03
	v14 = v14>>16 | v14<<48
	v09 += v14 + 2*uint64(uint32(v09))*uint64(uint32(v14))
	v04 ^= v09
	v04 = v04>>63 | v04<<1

	*t00, *t01, *t02, *t03 = v00, v01, v02, v03
	*t04, *t05, *t06, *t07 = v04, v05, v06, v07
	*t08, *t09, *t10, *t11 = v08, v09, v10, v11
	*t12, *t13, *t14, *t15 = v12, v13, v14, v15
}

func blake2bHash(out, in []byte) {
	var (
		d   hash.Hash
		err error
	)
	if len(out) < blake2b.Size {
		d, err = blake2b.New(len(out), nil)
	} else {
		d, err = blake2b.New512(nil)
	}
	if err != nil {
		panic("argon2id: blake2b init failed")
	}

	var sizeBuf [4]byte
	binary.LittleEndian.PutUint32(sizeBuf[:], uint32(len(out)))
	d.Write(sizeBuf[:])
	d.Write(in)

	if len(out) <= blake2b.Size {
		d.Sum(out[:0])
		return
	}

	var buffer [blake2b.Size]byte
	d.Sum(buffer[:0])
	copy(out, buffer[:32])
	out = out[32:]

	for len(out) > blake2b.Size {
		d.Reset()
		d.Write(buffer[:])
		d.Sum(buffer[:0])
		copy(out, buffer[:32])
		out = out[32:]
	}

	if len(out) > 0 {
		r, err := blake2b.New(len(out), nil)
		if err != nil {
			panic("argon2id: blake2b init failed")
		}
		r.Write(buffer[:])
		r.Sum(out[:0])
	}
}
