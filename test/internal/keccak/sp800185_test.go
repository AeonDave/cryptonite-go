package keccak_test

import (
	"bytes"
	_ "embed"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/AeonDave/cryptonite-go/internal/keccak"
	testutil "github.com/AeonDave/cryptonite-go/test/internal/testutil"
)

//go:embed testdata/sp800185_kat.txt
var sp800185KAT string

type sp800185Vectors struct {
	LeftEncode   []sp800185Value
	RightEncode  []sp800185Value
	EncodeString []struct {
		Data   string
		Output string
	}
	Bytepad []struct {
		Data   string
		W      int
		Output string
	}
}

type sp800185Value struct {
	Input  uint64
	Output string
}

func parseSP800185KAT(t *testing.T) sp800185Vectors {
	t.Helper()
	var vectors sp800185Vectors
	lines := strings.Split(sp800185KAT, "\n")
	for i := 0; i < len(lines); {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			i++
			continue
		}
		if !strings.HasPrefix(line, "Function =") {
			t.Fatalf("unexpected label at line %d: %q", i+1, lines[i])
		}
		fn := strings.TrimSpace(strings.TrimPrefix(line, "Function ="))
		switch fn {
		case "LeftEncode", "RightEncode":
			if i+2 >= len(lines) {
				t.Fatalf("incomplete %s block at line %d", fn, i+1)
			}
			inLine := strings.TrimSpace(lines[i+1])
			outLine := strings.TrimSpace(lines[i+2])
			if !strings.HasPrefix(inLine, "Input =") || !strings.HasPrefix(outLine, "Output =") {
				t.Fatalf("unexpected %s block format near line %d", fn, i+1)
			}
			inStr := strings.TrimSpace(strings.TrimPrefix(inLine, "Input ="))
			val, err := strconv.ParseUint(inStr, 10, 64)
			if err != nil {
				t.Fatalf("invalid input %q near line %d: %v", inStr, i+1, err)
			}
			outStr := strings.TrimSpace(strings.TrimPrefix(outLine, "Output ="))
			v := sp800185Value{Input: val, Output: outStr}
			if fn == "LeftEncode" {
				vectors.LeftEncode = append(vectors.LeftEncode, v)
			} else {
				vectors.RightEncode = append(vectors.RightEncode, v)
			}
			i += 3
		case "EncodeString":
			if i+2 >= len(lines) {
				t.Fatalf("incomplete EncodeString block at line %d", i+1)
			}
			dataLine := strings.TrimSpace(lines[i+1])
			outLine := strings.TrimSpace(lines[i+2])
			if !strings.HasPrefix(dataLine, "Data =") || !strings.HasPrefix(outLine, "Output =") {
				t.Fatalf("unexpected EncodeString block format near line %d", i+1)
			}
			dataStr := strings.TrimSpace(strings.TrimPrefix(dataLine, "Data ="))
			outStr := strings.TrimSpace(strings.TrimPrefix(outLine, "Output ="))
			vectors.EncodeString = append(vectors.EncodeString, struct {
				Data   string
				Output string
			}{Data: dataStr, Output: outStr})
			i += 3
		case "Bytepad":
			if i+3 >= len(lines) {
				t.Fatalf("incomplete Bytepad block at line %d", i+1)
			}
			dataLine := strings.TrimSpace(lines[i+1])
			wLine := strings.TrimSpace(lines[i+2])
			outLine := strings.TrimSpace(lines[i+3])
			if !strings.HasPrefix(dataLine, "Data =") || !strings.HasPrefix(wLine, "W =") || !strings.HasPrefix(outLine, "Output =") {
				t.Fatalf("unexpected Bytepad block format near line %d", i+1)
			}
			dataStr := strings.TrimSpace(strings.TrimPrefix(dataLine, "Data ="))
			wStr := strings.TrimSpace(strings.TrimPrefix(wLine, "W ="))
			w, err := strconv.Atoi(wStr)
			if err != nil {
				t.Fatalf("invalid W %q near line %d: %v", wStr, i+1, err)
			}
			outStr := strings.TrimSpace(strings.TrimPrefix(outLine, "Output ="))
			vectors.Bytepad = append(vectors.Bytepad, struct {
				Data   string
				W      int
				Output string
			}{Data: dataStr, W: w, Output: outStr})
			i += 4
		default:
			t.Fatalf("unknown Function %q at line %d", fn, i+1)
		}
		if i < len(lines) && strings.TrimSpace(lines[i]) == "" {
			i++
		}
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
