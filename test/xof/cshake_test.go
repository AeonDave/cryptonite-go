package xof_test

import (
	"bytes"
	_ "embed"
	"strconv"
	"strings"
	"testing"

	testutil "github.com/AeonDave/cryptonite-go/test/internal/testutil"
	"github.com/AeonDave/cryptonite-go/xof"
)

//go:embed testdata/cshake_kat.txt
var cshakeKAT string

type cshakeVectors struct {
	CSHAKE128 []cshakeVector `json:"cshake128"`
	CSHAKE256 []cshakeVector `json:"cshake256"`
}

type cshakeVector struct {
	Name          string `json:"name"`
	FunctionName  string `json:"function_name"`
	Customization string `json:"customization"`
	Message       string `json:"message"`
	OutLen        int    `json:"out_len"`
	Digest        string `json:"digest"`
}

func parseCSHAKEVectors(t *testing.T) cshakeVectors {
	t.Helper()
	var vectors cshakeVectors
	lines := strings.Split(cshakeKAT, "\n")
	for i := 0; i < len(lines); {
		line := strings.TrimSpace(lines[i])
		if line == "" || strings.HasPrefix(line, "#") {
			i++
			continue
		}
		if !strings.HasPrefix(line, "Variant =") {
			t.Fatalf("unexpected label at line %d: %q", i+1, lines[i])
		}
		variant := strings.TrimSpace(strings.TrimPrefix(line, "Variant ="))
		if i+5 >= len(lines) {
			t.Fatalf("incomplete block at line %d", i+1)
		}
		fnLine := strings.TrimSpace(lines[i+1])
		custLine := strings.TrimSpace(lines[i+2])
		msgLine := strings.TrimSpace(lines[i+3])
		outLenLine := strings.TrimSpace(lines[i+4])
		digLine := strings.TrimSpace(lines[i+5])
		if !strings.HasPrefix(fnLine, "FunctionName =") || !strings.HasPrefix(custLine, "Customization =") ||
			!strings.HasPrefix(msgLine, "Msg =") || !strings.HasPrefix(outLenLine, "OutLen =") ||
			!strings.HasPrefix(digLine, "Digest =") {
			t.Fatalf("unexpected block format near line %d", i+1)
		}
		fn := strings.TrimSpace(strings.TrimPrefix(fnLine, "FunctionName ="))
		cust := strings.TrimSpace(strings.TrimPrefix(custLine, "Customization ="))
		msg := strings.TrimSpace(strings.TrimPrefix(msgLine, "Msg ="))
		outLenStr := strings.TrimSpace(strings.TrimPrefix(outLenLine, "OutLen ="))
		outLen, err := strconv.Atoi(outLenStr)
		if err != nil {
			t.Fatalf("invalid OutLen %q near line %d: %v", outLenStr, i+1, err)
		}
		dig := strings.TrimSpace(strings.TrimPrefix(digLine, "Digest ="))
		v := cshakeVector{
			Name:          "",
			FunctionName:  fn,
			Customization: cust,
			Message:       msg,
			OutLen:        outLen,
			Digest:        dig,
		}
		switch strings.ToUpper(variant) {
		case "CSHAKE128":
			vectors.CSHAKE128 = append(vectors.CSHAKE128, v)
		case "CSHAKE256":
			vectors.CSHAKE256 = append(vectors.CSHAKE256, v)
		default:
			t.Fatalf("unknown variant %q at line %d", variant, i+1)
		}
		i += 6
		if i < len(lines) && strings.TrimSpace(lines[i]) == "" {
			i++
		}
	}
	return vectors
}

func TestCSHAKE128KAT(t *testing.T) {
	vectors := parseCSHAKEVectors(t)
	if len(vectors.CSHAKE128) == 0 {
		t.Fatal("no cSHAKE128 vectors present")
	}
	for _, tc := range vectors.CSHAKE128 {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			fn := testutil.MustHex(t, tc.FunctionName)
			customization := testutil.MustHex(t, tc.Customization)
			msg := testutil.MustHex(t, tc.Message)
			want := testutil.MustHex(t, tc.Digest)
			out := make([]byte, tc.OutLen)
			cs := xof.CSHAKE128(fn, customization)
			if _, err := cs.Write(msg); err != nil {
				t.Fatalf("Write failed: %v", err)
			}
			if _, err := cs.Read(out); err != nil {
				t.Fatalf("Read failed: %v", err)
			}
			if !bytes.Equal(out, want) {
				t.Fatalf("unexpected digest\n got  %x\n want %x", out, want)
			}
		})
	}
}

func TestCSHAKE256KAT(t *testing.T) {
	vectors := parseCSHAKEVectors(t)
	if len(vectors.CSHAKE256) == 0 {
		t.Fatal("no cSHAKE256 vectors present")
	}
	for _, tc := range vectors.CSHAKE256 {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			fn := testutil.MustHex(t, tc.FunctionName)
			customization := testutil.MustHex(t, tc.Customization)
			msg := testutil.MustHex(t, tc.Message)
			want := testutil.MustHex(t, tc.Digest)
			got := xof.SumCSHAKE256(fn, customization, msg, tc.OutLen)
			if !bytes.Equal(got, want) {
				t.Fatalf("unexpected digest\n got  %x\n want %x", got, want)
			}
		})
	}
}

func TestCSHAKEReset(t *testing.T) {
	cs := xof.CSHAKE128(nil, nil)
	msg := []byte("reset message")
	out1 := make([]byte, 32)
	out2 := make([]byte, 32)
	if _, err := cs.Write(msg); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if _, err := cs.Read(out1); err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	cs.Reset()
	if _, err := cs.Write(msg); err != nil {
		t.Fatalf("Write after reset failed: %v", err)
	}
	if _, err := cs.Read(out2); err != nil {
		t.Fatalf("Read after reset failed: %v", err)
	}
	if !bytes.Equal(out1, out2) {
		t.Fatalf("Reset produced inconsistent output")
	}
}
