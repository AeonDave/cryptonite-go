package xof_test

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"testing"

	testutil "github.com/AeonDave/cryptonite-go/test/internal/testutil"
	"github.com/AeonDave/cryptonite-go/xof"
)

//go:embed testdata/cshake_kat.json
var cshakeKAT []byte

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
	if err := json.Unmarshal(cshakeKAT, &vectors); err != nil {
		t.Fatalf("failed to unmarshal cSHAKE KAT: %v", err)
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
