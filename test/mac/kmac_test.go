package mac_test

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"testing"

	"github.com/AeonDave/cryptonite-go/mac"
	testutil "github.com/AeonDave/cryptonite-go/test/internal/testutil"
)

//go:embed testdata/kmac_kat.json
var kmacKAT []byte

type kmacVectors struct {
	KMAC128 []kmacVector `json:"kmac128"`
	KMAC256 []kmacVector `json:"kmac256"`
}

type kmacVector struct {
	Name          string `json:"name"`
	Key           string `json:"key"`
	Customization string `json:"customization"`
	Message       string `json:"message"`
	OutLen        int    `json:"out_len"`
	Mac           string `json:"mac"`
}

func parseKMACVectors(t *testing.T) kmacVectors {
	t.Helper()
	var vectors kmacVectors
	if err := json.Unmarshal(kmacKAT, &vectors); err != nil {
		t.Fatalf("failed to unmarshal KMAC KAT: %v", err)
	}
	return vectors
}

func TestKMAC128KAT(t *testing.T) {
	vectors := parseKMACVectors(t)
	if len(vectors.KMAC128) == 0 {
		t.Fatal("no KMAC128 test vectors present")
	}
	for _, tc := range vectors.KMAC128 {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			key := testutil.MustHex(t, tc.Key)
			customization := testutil.MustHex(t, tc.Customization)
			msg := testutil.MustHex(t, tc.Message)
			got := mac.KMAC128(key, customization, msg, tc.OutLen)
			want := testutil.MustHex(t, tc.Mac)
			if !bytes.Equal(got, want) {
				t.Fatalf("unexpected MAC\n got  %x\n want %x", got, want)
			}
		})
	}
}

func TestKMAC256KAT(t *testing.T) {
	vectors := parseKMACVectors(t)
	if len(vectors.KMAC256) == 0 {
		t.Fatal("no KMAC256 test vectors present")
	}
	for _, tc := range vectors.KMAC256 {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			key := testutil.MustHex(t, tc.Key)
			customization := testutil.MustHex(t, tc.Customization)
			msg := testutil.MustHex(t, tc.Message)
			h := mac.NewKMAC256(key, customization)
			if _, err := h.Write(msg); err != nil {
				t.Fatalf("Write failed: %v", err)
			}
			sum1 := h.Sum(nil)
			if gotLen := len(sum1); gotLen != tc.OutLen {
				t.Fatalf("unexpected MAC length: got %d want %d", gotLen, tc.OutLen)
			}
			sum2 := h.Sum(nil)
			if !bytes.Equal(sum1, sum2) {
				t.Fatalf("Sum altered internal state")
			}
			want := testutil.MustHex(t, tc.Mac)
			if !bytes.Equal(sum1, want) {
				t.Fatalf("unexpected MAC\n got  %x\n want %x", sum1, want)
			}
		})
	}
}

func TestKMACReset(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 16)
	msg := []byte("reset test")
	h := mac.NewKMAC128WithSize(key, nil, 16)
	if _, err := h.Write(msg); err != nil {
		t.Fatalf("initial Write failed: %v", err)
	}
	first := h.Sum(nil)
	h.Reset()
	if _, err := h.Write(msg); err != nil {
		t.Fatalf("Write after Reset failed: %v", err)
	}
	second := h.Sum(nil)
	if !bytes.Equal(first, second) {
		t.Fatalf("Reset did not reproduce the same MAC")
	}
}
