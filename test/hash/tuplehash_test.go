package xoodyak_test

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	_ "embed"

	cryptohash "github.com/AeonDave/cryptonite-go/hash"
)

//go:embed testdata/tuple_parallel_kat.json
var tupleParallelKAT []byte

type tupleCase struct {
	Tuple         []string `json:"tuple"`
	Customization string   `json:"customization"`
	OutLen        int      `json:"out_len"`
	Digest        string   `json:"digest"`
}

type parallelCase struct {
	Message       string `json:"message"`
	BlockSize     int    `json:"block_size"`
	Customization string `json:"customization"`
	OutLen        int    `json:"out_len"`
	Digest        string `json:"digest"`
}

type tupleParallelVectors struct {
	TupleHash128    []tupleCase    `json:"tuplehash128"`
	TupleHash256    []tupleCase    `json:"tuplehash256"`
	ParallelHash128 []parallelCase `json:"parallelhash128"`
	ParallelHash256 []parallelCase `json:"parallelhash256"`
}

func TestTupleHashKAT(t *testing.T) {
	var vectors tupleParallelVectors
	if err := json.Unmarshal(tupleParallelKAT, &vectors); err != nil {
		t.Fatalf("failed to decode vectors: %v", err)
	}
	for idx, tc := range vectors.TupleHash128 {
		tuple := decodeTuple(t, tc.Tuple)
		digest := mustHex(t, tc.Digest)
		out, err := cryptohash.TupleHash128(tuple, tc.OutLen, mustHex(t, tc.Customization))
		if err != nil {
			t.Fatalf("TupleHash128 vector %d failed: %v", idx, err)
		}
		if !bytesEqual(out, digest) {
			t.Fatalf("TupleHash128 vector %d mismatch\n got %x\nwant %x", idx, out, digest)
		}
	}
	for idx, tc := range vectors.TupleHash256 {
		tuple := decodeTuple(t, tc.Tuple)
		digest := mustHex(t, tc.Digest)
		out, err := cryptohash.TupleHash256(tuple, tc.OutLen, mustHex(t, tc.Customization))
		if err != nil {
			t.Fatalf("TupleHash256 vector %d failed: %v", idx, err)
		}
		if !bytesEqual(out, digest) {
			t.Fatalf("TupleHash256 vector %d mismatch\n got %x\nwant %x", idx, out, digest)
		}
	}
}

func TestParallelHashKAT(t *testing.T) {
	var vectors tupleParallelVectors
	if err := json.Unmarshal(tupleParallelKAT, &vectors); err != nil {
		t.Fatalf("failed to decode vectors: %v", err)
	}
	for idx, tc := range vectors.ParallelHash128 {
		msg := mustHex(t, tc.Message)
		digest := mustHex(t, tc.Digest)
		out, err := cryptohash.ParallelHash128(msg, tc.BlockSize, tc.OutLen, mustHex(t, tc.Customization))
		if err != nil {
			t.Fatalf("ParallelHash128 vector %d failed: %v", idx, err)
		}
		if !bytesEqual(out, digest) {
			t.Fatalf("ParallelHash128 vector %d mismatch\n got %x\nwant %x", idx, out, digest)
		}
	}
	for idx, tc := range vectors.ParallelHash256 {
		msg := mustHex(t, tc.Message)
		digest := mustHex(t, tc.Digest)
		out, err := cryptohash.ParallelHash256(msg, tc.BlockSize, tc.OutLen, mustHex(t, tc.Customization))
		if err != nil {
			t.Fatalf("ParallelHash256 vector %d failed: %v", idx, err)
		}
		if !bytesEqual(out, digest) {
			t.Fatalf("ParallelHash256 vector %d mismatch\n got %x\nwant %x", idx, out, digest)
		}
	}
}

func decodeTuple(t *testing.T, enc []string) [][]byte {
	t.Helper()
	out := make([][]byte, len(enc))
	for i, item := range enc {
		out[i] = mustHex(t, item)
	}
	return out
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	if s == "" {
		return nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("invalid hex %q: %v", s, err)
	}
	return b
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
