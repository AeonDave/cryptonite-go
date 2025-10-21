package mac_test

import (
	"bytes"
	_ "embed"
	"fmt"
	"strings"
	"testing"

	"github.com/AeonDave/cryptonite-go/mac"
	testutil "github.com/AeonDave/cryptonite-go/test/internal/testutil"
)

//go:embed testdata/hmac_sha256_kat.txt
var hmacSHA256KAT string

type hmacCase struct {
	key []byte
	msg []byte
	tag []byte
}

func parseHMACSHA256KAT(t *testing.T) []hmacCase {
	t.Helper()
	var cases []hmacCase
	blocks := strings.Split(strings.TrimSpace(hmacSHA256KAT), "\n\n")
	for i, block := range blocks {
		if strings.HasPrefix(block, "#") {
			if idx := strings.Index(block, "\n"); idx >= 0 {
				block = block[idx+1:]
			} else {
				continue
			}
		}
		var keyHex, msgHex, tagHex string
		for _, line := range strings.Split(block, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				t.Fatalf("invalid line in block %d: %q", i+1, line)
			}
			label := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			switch label {
			case "Key":
				keyHex = value
			case "Msg":
				msgHex = value
			case "Tag":
				tagHex = value
			default:
				t.Fatalf("unexpected label %q in block %d", label, i+1)
			}
		}
		if keyHex == "" || msgHex == "" || tagHex == "" {
			t.Fatalf("missing fields in block %d", i+1)
		}
		cases = append(cases, hmacCase{
			key: testutil.MustHex(t, keyHex),
			msg: testutil.MustHex(t, msgHex),
			tag: testutil.MustHex(t, tagHex),
		})
	}
	if len(cases) == 0 {
		t.Fatal("no HMAC-SHA256 KAT cases parsed")
	}
	return cases
}

func TestHMACSHA256KAT(t *testing.T) {
	cases := parseHMACSHA256KAT(t)
	for idx, tc := range cases {
		tc := tc
		t.Run(fmt.Sprintf("case_%d", idx+1), func(t *testing.T) {
			got := mac.Sum(tc.key, tc.msg)
			if !bytes.Equal(got, tc.tag) {
				t.Fatalf("case %d: unexpected MAC\n got %x\nwant %x", idx+1, got, tc.tag)
			}
			if !mac.Verify(tc.key, tc.msg, tc.tag) {
				t.Fatalf("case %d: Verify rejected valid MAC", idx+1)
			}
			keyCopy := append([]byte(nil), tc.key...)
			msgCopy := append([]byte(nil), tc.msg...)
			tagCopy := append([]byte(nil), tc.tag...)
			if !mac.Verify(keyCopy, msgCopy, tagCopy) {
				t.Fatalf("case %d: Verify rejected MAC with separate buffers", idx+1)
			}
		})
	}
}

func TestHMACSHA256VerifyRejectsInvalid(t *testing.T) {
	cases := parseHMACSHA256KAT(t)
	tc := cases[0]
	truncated := tc.tag[:len(tc.tag)-1]
	if mac.Verify(tc.key, tc.msg, truncated) {
		t.Fatal("Verify accepted truncated MAC")
	}
	tampered := append([]byte(nil), tc.tag...)
	tampered[0] ^= 0xff
	if mac.Verify(tc.key, tc.msg, tampered) {
		t.Fatal("Verify accepted tampered MAC")
	}
}
