package xoodyak_test

import (
	"bytes"
	_ "embed"
	stdhash "hash"
	"io"
	"strconv"
	"strings"
	"testing"

	cryptohash "cryptonite-go/hash"
	testutil "cryptonite-go/test/internal/testutil"
)

//go:embed testdata/blake2_kat.txt
var blake2KAT string

type blake2Case struct {
	variant string
	key     []byte
	msg     []byte
	md      []byte
	outLen  int
	mode    string
}

func parseBlake2KAT(t *testing.T) []blake2Case {
	t.Helper()
	lines := strings.Split(blake2KAT, "\n")
	var cases []blake2Case
	for i := 0; i < len(lines); {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			i++
			continue
		}
		if !strings.HasPrefix(line, "Variant =") {
			t.Fatalf("unexpected label on line %d: %q", i+1, lines[i])
		}
		variant := strings.TrimSpace(strings.TrimPrefix(line, "Variant ="))
		i++
		var (
			key, msg, md []byte
			outLen       int
			mode         = "KNOWN"
		)
		for i < len(lines) {
			l := strings.TrimSpace(lines[i])
			if l == "" {
				i++
				break
			}
			switch {
			case strings.HasPrefix(l, "Key ="):
				key = testutil.MustHex(t, strings.TrimSpace(strings.TrimPrefix(l, "Key =")))
			case strings.HasPrefix(l, "Msg ="):
				msg = testutil.MustHex(t, strings.TrimSpace(strings.TrimPrefix(l, "Msg =")))
			case strings.HasPrefix(l, "MD ="):
				md = testutil.MustHex(t, strings.TrimSpace(strings.TrimPrefix(l, "MD =")))
			case strings.HasPrefix(l, "OutLen ="):
				value := strings.TrimSpace(strings.TrimPrefix(l, "OutLen ="))
				if value != "" {
					n, err := strconv.Atoi(value)
					if err != nil {
						t.Fatalf("invalid OutLen on line %d: %v", i+1, err)
					}
					outLen = n
				}
			case strings.HasPrefix(l, "Mode ="):
				mode = strings.ToUpper(strings.TrimSpace(strings.TrimPrefix(l, "Mode =")))
			default:
				t.Fatalf("unexpected attribute on line %d: %q", i+1, lines[i])
			}
			i++
		}
		cases = append(cases, blake2Case{
			variant: variant,
			key:     key,
			msg:     msg,
			md:      md,
			outLen:  outLen,
			mode:    mode,
		})
	}
	return cases
}

func TestBlake2KAT(t *testing.T) {
	cases := parseBlake2KAT(t)
	if len(cases) == 0 {
		t.Fatal("no BLAKE2 cases parsed")
	}
	for idx, tc := range cases {
		switch {
		case strings.HasPrefix(tc.variant, "BLAKE2b-XOF"):
			testBlake2bXOF(t, idx, tc)
		case strings.HasPrefix(tc.variant, "BLAKE2s-XOF"):
			testBlake2sXOF(t, idx, tc)
		case strings.HasPrefix(tc.variant, "BLAKE2b-"):
			testBlake2Digest(t, idx, tc, true)
		case strings.HasPrefix(tc.variant, "BLAKE2s-"):
			testBlake2Digest(t, idx, tc, false)
		default:
			t.Fatalf("case %d: unknown variant %q", idx+1, tc.variant)
		}
	}
}

func testBlake2Digest(t *testing.T, idx int, tc blake2Case, isB bool) {
	t.Helper()
	sizeStr := strings.TrimPrefix(tc.variant, "BLAKE2b-")
	if !isB {
		sizeStr = strings.TrimPrefix(tc.variant, "BLAKE2s-")
	}
	sizeBits, err := strconv.Atoi(sizeStr)
	if err != nil {
		t.Fatalf("case %d: invalid size in variant %q: %v", idx+1, tc.variant, err)
	}
	if sizeBits%8 != 0 {
		t.Fatalf("case %d: size not byte-aligned: %d", idx+1, sizeBits)
	}
	size := sizeBits / 8
	var builder interface {
		Hash() (stdhash.Hash, error)
		Hasher() (cryptohash.Hasher, error)
		Sum([]byte) ([]byte, error)
	}
	if isB {
		b := cryptohash.NewBlake2bBuilder().Size(size)
		if len(tc.key) > 0 {
			b = b.Key(tc.key)
		}
		builder = b
	} else {
		b := cryptohash.NewBlake2sBuilder().Size(size)
		if len(tc.key) > 0 {
			b = b.Key(tc.key)
		}
		builder = b
	}
	verifyBlake2Digest(t, idx, tc, size, isB, builder)
}

func verifyBlake2Digest(t *testing.T, idx int, tc blake2Case, size int, isB bool, builder interface {
	Hash() (stdhash.Hash, error)
	Hasher() (cryptohash.Hasher, error)
	Sum([]byte) ([]byte, error)
}) {
	t.Helper()
	stream, err := builder.Hash()
	if err != nil {
		t.Fatalf("case %d: Hash constructor failed: %v", idx+1, err)
	}
	if _, err := stream.Write(tc.msg); err != nil {
		t.Fatalf("case %d: initial write failed: %v", idx+1, err)
	}
	if got := stream.Sum(nil); !bytes.Equal(got, tc.md) {
		t.Fatalf("case %d: digest mismatch\n got %x\nwant %x", idx+1, got, tc.md)
	}
	stream.Reset()
	if len(tc.msg) > 0 {
		split := len(tc.msg) / 2
		if split == 0 {
			split = len(tc.msg)
		}
		if _, err := stream.Write(tc.msg[:split]); err != nil {
			t.Fatalf("case %d: split write failed: %v", idx+1, err)
		}
		if _, err := stream.Write(tc.msg[split:]); err != nil {
			t.Fatalf("case %d: second split write failed: %v", idx+1, err)
		}
	}
	if got := stream.Sum(nil); !bytes.Equal(got, tc.md) {
		t.Fatalf("case %d: digest mismatch after reset", idx+1)
	}
	stateless, err := builder.Hasher()
	if err != nil {
		t.Fatalf("case %d: Hasher constructor failed: %v", idx+1, err)
	}
	if stateless.Size() != len(tc.md) {
		t.Fatalf("case %d: unexpected size: got %d want %d", idx+1, stateless.Size(), len(tc.md))
	}
	if got := stateless.Hash(tc.msg); !bytes.Equal(got, tc.md) {
		t.Fatalf("case %d: stateless digest mismatch", idx+1)
	}
	sum, err := builder.Sum(tc.msg)
	if err != nil {
		t.Fatalf("case %d: Sum failed: %v", idx+1, err)
	}
	if !bytes.Equal(sum, tc.md) {
		t.Fatalf("case %d: Sum mismatch", idx+1)
	}
	if isB {
		direct, err := cryptohash.NewBlake2b(size, tc.key)
		if err != nil {
			t.Fatalf("case %d: NewBlake2b failed: %v", idx+1, err)
		}
		if _, err := direct.Write(tc.msg); err != nil {
			t.Fatalf("case %d: direct write failed: %v", idx+1, err)
		}
		if got := direct.Sum(nil); !bytes.Equal(got, tc.md) {
			t.Fatalf("case %d: direct digest mismatch", idx+1)
		}
		statelessDirect, err := cryptohash.NewBlake2bHasher(size, tc.key)
		if err != nil {
			t.Fatalf("case %d: NewBlake2bHasher failed: %v", idx+1, err)
		}
		if got := statelessDirect.Hash(tc.msg); !bytes.Equal(got, tc.md) {
			t.Fatalf("case %d: NewBlake2bHasher mismatch", idx+1)
		}
	} else {
		direct, err := cryptohash.NewBlake2s(size, tc.key)
		if err != nil {
			t.Fatalf("case %d: NewBlake2s failed: %v", idx+1, err)
		}
		if _, err := direct.Write(tc.msg); err != nil {
			t.Fatalf("case %d: direct write failed: %v", idx+1, err)
		}
		if got := direct.Sum(nil); !bytes.Equal(got, tc.md) {
			t.Fatalf("case %d: direct digest mismatch", idx+1)
		}
		statelessDirect, err := cryptohash.NewBlake2sHasher(size, tc.key)
		if err != nil {
			t.Fatalf("case %d: NewBlake2sHasher failed: %v", idx+1, err)
		}
		if got := statelessDirect.Hash(tc.msg); !bytes.Equal(got, tc.md) {
			t.Fatalf("case %d: NewBlake2sHasher mismatch", idx+1)
		}
	}
}

func testBlake2bXOF(t *testing.T, idx int, tc blake2Case) {
	t.Helper()
	builder := cryptohash.NewBlake2bBuilder()
	if len(tc.key) > 0 {
		builder = builder.Key(tc.key)
	}
	length := uint32(tc.outLen)
	if strings.EqualFold(tc.mode, "UNKNOWN") {
		length = cryptohash.Blake2bXOFUnknown
	}
	x, err := builder.XOF(length)
	if err != nil {
		t.Fatalf("case %d: XOF constructor failed: %v", idx+1, err)
	}
	if _, err := x.Write(tc.msg); err != nil {
		t.Fatalf("case %d: XOF write failed: %v", idx+1, err)
	}
	got := readXOF(t, x, tc.outLen)
	if !bytes.Equal(got, tc.md) {
		t.Fatalf("case %d: XOF mismatch", idx+1)
	}
	x.Reset()
	if _, err := x.Write(tc.msg); err != nil {
		t.Fatalf("case %d: XOF write after reset failed: %v", idx+1, err)
	}
	if got2 := readXOF(t, x, tc.outLen); !bytes.Equal(got2, tc.md) {
		t.Fatalf("case %d: XOF mismatch after reset", idx+1)
	}
	if !strings.EqualFold(tc.mode, "UNKNOWN") {
		direct, err := cryptohash.NewBlake2bXOF(uint32(tc.outLen), tc.key)
		if err != nil {
			t.Fatalf("case %d: NewBlake2bXOF failed: %v", idx+1, err)
		}
		if _, err := direct.Write(tc.msg); err != nil {
			t.Fatalf("case %d: direct XOF write failed: %v", idx+1, err)
		}
		if got3 := readXOF(t, direct, tc.outLen); !bytes.Equal(got3, tc.md) {
			t.Fatalf("case %d: direct XOF mismatch", idx+1)
		}
	}
}

func testBlake2sXOF(t *testing.T, idx int, tc blake2Case) {
	t.Helper()
	builder := cryptohash.NewBlake2sBuilder()
	if len(tc.key) > 0 {
		builder = builder.Key(tc.key)
	}
	length := uint32(tc.outLen)
	if strings.EqualFold(tc.mode, "UNKNOWN") {
		length = cryptohash.Blake2sXOFUnknown
	}
	x, err := builder.XOF(length)
	if err != nil {
		t.Fatalf("case %d: XOF constructor failed: %v", idx+1, err)
	}
	if _, err := x.Write(tc.msg); err != nil {
		t.Fatalf("case %d: XOF write failed: %v", idx+1, err)
	}
	got := readXOF(t, x, tc.outLen)
	if !bytes.Equal(got, tc.md) {
		t.Fatalf("case %d: XOF mismatch", idx+1)
	}
	x.Reset()
	if _, err := x.Write(tc.msg); err != nil {
		t.Fatalf("case %d: XOF write after reset failed: %v", idx+1, err)
	}
	if got2 := readXOF(t, x, tc.outLen); !bytes.Equal(got2, tc.md) {
		t.Fatalf("case %d: XOF mismatch after reset", idx+1)
	}
	if !strings.EqualFold(tc.mode, "UNKNOWN") {
		direct, err := cryptohash.NewBlake2sXOF(uint32(tc.outLen), tc.key)
		if err != nil {
			t.Fatalf("case %d: NewBlake2sXOF failed: %v", idx+1, err)
		}
		if _, err := direct.Write(tc.msg); err != nil {
			t.Fatalf("case %d: direct XOF write failed: %v", idx+1, err)
		}
		if got3 := readXOF(t, direct, tc.outLen); !bytes.Equal(got3, tc.md) {
			t.Fatalf("case %d: direct XOF mismatch", idx+1)
		}
	}
}

func readXOF(t *testing.T, x *cryptohash.XOF, length int) []byte {
	t.Helper()
	out := make([]byte, length)
	offset := 0
	for offset < length {
		n, err := x.Read(out[offset:])
		offset += n
		if err == io.EOF {
			if offset != length {
				t.Fatalf("unexpected EOF after %d bytes (want %d)", offset, length)
			}
			break
		}
		if err != nil {
			t.Fatalf("read failed: %v", err)
		}
		if n == 0 {
			t.Fatalf("zero-length read while %d bytes short", length-offset)
		}
	}
	return out
}
