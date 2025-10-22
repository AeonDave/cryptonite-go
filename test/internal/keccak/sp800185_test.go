package keccak_test

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/AeonDave/cryptonite-go/internal/keccak"
	testutil "github.com/AeonDave/cryptonite-go/test/internal/testutil"
)

//go:embed testdata/sp800185_kat.json
var sp800185KAT []byte

type sp800185Vectors struct {
	LeftEncode   []sp800185Value `json:"left_encode"`
	RightEncode  []sp800185Value `json:"right_encode"`
	EncodeString []struct {
		Data   string `json:"data"`
		Output string `json:"output"`
	} `json:"encode_string"`
	Bytepad []struct {
		Data   string `json:"data"`
		W      int    `json:"w"`
		Output string `json:"output"`
	} `json:"bytepad"`
}

type sp800185Value struct {
	Input  uint64 `json:"input"`
	Output string `json:"output"`
}

func parseSP800185KAT(t *testing.T) sp800185Vectors {
	t.Helper()
	var vectors sp800185Vectors
	if err := json.Unmarshal(sp800185KAT, &vectors); err != nil {
		t.Fatalf("failed to unmarshal SP 800-185 KAT: %v", err)
	}
	return vectors
}

func TestLeftEncodeKAT(t *testing.T) {
	vectors := parseSP800185KAT(t)
	for idx, tc := range vectors.LeftEncode {
		tc := tc
		t.Run(fmt.Sprintf("left_%d", idx), func(t *testing.T) {
			got := keccak.LeftEncode(tc.Input)
			want := testutil.MustHex(t, tc.Output)
			if !bytes.Equal(got, want) {
				t.Fatalf("LeftEncode(%d) = %x, want %x", tc.Input, got, want)
			}
		})
	}
}

func TestRightEncodeKAT(t *testing.T) {
	vectors := parseSP800185KAT(t)
	for idx, tc := range vectors.RightEncode {
		tc := tc
		t.Run(fmt.Sprintf("right_%d", idx), func(t *testing.T) {
			got := keccak.RightEncode(tc.Input)
			want := testutil.MustHex(t, tc.Output)
			if !bytes.Equal(got, want) {
				t.Fatalf("RightEncode(%d) = %x, want %x", tc.Input, got, want)
			}
		})
	}
}

func TestEncodeStringKAT(t *testing.T) {
	vectors := parseSP800185KAT(t)
	for idx, tc := range vectors.EncodeString {
		tc := tc
		t.Run(fmt.Sprintf("encode_string_%d", idx), func(t *testing.T) {
			data := testutil.MustHex(t, tc.Data)
			got := keccak.EncodeString(data)
			want := testutil.MustHex(t, tc.Output)
			if !bytes.Equal(got, want) {
				t.Fatalf("EncodeString(%x) = %x, want %x", data, got, want)
			}
		})
	}
}

func TestBytepadKAT(t *testing.T) {
	vectors := parseSP800185KAT(t)
	for idx, tc := range vectors.Bytepad {
		tc := tc
		t.Run(fmt.Sprintf("bytepad_%d", idx), func(t *testing.T) {
			data := testutil.MustHex(t, tc.Data)
			got := keccak.Bytepad(data, tc.W)
			want := testutil.MustHex(t, tc.Output)
			if !bytes.Equal(got, want) {
				t.Fatalf("Bytepad mismatch\n got  %x\n want %x", got, want)
			}
		})
	}
}
