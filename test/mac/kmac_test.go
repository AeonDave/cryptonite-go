package mac_test

import (
	"bytes"
	_ "embed"
	"strconv"
	"strings"
	"testing"

	"github.com/AeonDave/cryptonite-go/mac"
	testutil "github.com/AeonDave/cryptonite-go/test/internal/testutil"
)

//go:embed testdata/kmac_kat.txt
var kmacKAT string

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
	lines := strings.Split(kmacKAT, "\n")
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
		keyLine := strings.TrimSpace(lines[i+1])
		custLine := strings.TrimSpace(lines[i+2])
		msgLine := strings.TrimSpace(lines[i+3])
		outLenLine := strings.TrimSpace(lines[i+4])
		macLine := strings.TrimSpace(lines[i+5])
		if !strings.HasPrefix(keyLine, "Key =") || !strings.HasPrefix(custLine, "Customization =") ||
			!strings.HasPrefix(msgLine, "Msg =") || !strings.HasPrefix(outLenLine, "OutLen =") ||
			!strings.HasPrefix(macLine, "MAC =") {
			t.Fatalf("unexpected block format near line %d", i+1)
		}
		_ = testutil.MustHex(t, strings.TrimSpace(strings.TrimPrefix(keyLine, "Key =")))
		_ = testutil.MustHex(t, strings.TrimSpace(strings.TrimPrefix(custLine, "Customization =")))
		_ = testutil.MustHex(t, strings.TrimSpace(strings.TrimPrefix(msgLine, "Msg =")))
		outLenStr := strings.TrimSpace(strings.TrimPrefix(outLenLine, "OutLen ="))
		outLen, err := strconv.Atoi(outLenStr)
		if err != nil {
			t.Fatalf("invalid OutLen %q near line %d: %v", outLenStr, i+1, err)
		}
		macHex := strings.TrimSpace(strings.TrimPrefix(macLine, "MAC ="))
		macBytes := testutil.MustHex(t, macHex)
		v := kmacVector{
			Name:          "",
			Key:           strings.TrimSpace(strings.TrimPrefix(keyLine, "Key =")),
			Customization: strings.TrimSpace(strings.TrimPrefix(custLine, "Customization =")),
			Message:       strings.TrimSpace(strings.TrimPrefix(msgLine, "Msg =")),
			OutLen:        outLen,
			Mac:           strings.TrimSpace(strings.TrimPrefix(macLine, "MAC =")),
		}
		// Assign to appropriate variant slices to keep existing tests.
		switch strings.ToUpper(variant) {
		case "KMAC128":
			vectors.KMAC128 = append(vectors.KMAC128, v)
		case "KMAC256":
			vectors.KMAC256 = append(vectors.KMAC256, v)
		default:
			t.Fatalf("unknown variant %q at line %d", variant, i+1)
		}
		// sanity check length matches provided MAC
		if len(macBytes) != outLen {
			t.Fatalf("MAC length (%d) does not match OutLen (%d) near line %d", len(macBytes), outLen, i+1)
		}
		i += 6
		if i < len(lines) && strings.TrimSpace(lines[i]) == "" {
			i++
		}
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
