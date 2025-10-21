package aead_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/AeonDave/cryptonite-go/aead"
	testutil "github.com/AeonDave/cryptonite-go/test/internal/testutil"
)

type aesSIVVector struct {
	name       string
	key        string
	nonce      string
	ad         []string
	singleAD   string
	plaintext  string
	tag        string
	ciphertext string
	useMulti   bool
}

var aesSIVVectors = []aesSIVVector{
	{
		name:       "rfc5297_deterministic",
		key:        "fffefdfc fbfaf9f8 f7f6f5f4 f3f2f1f0 f0f1f2f3 f4f5f6f7 f8f9fafb fcfdfeff",
		nonce:      "",
		singleAD:   "10111213 14151617 18191a1b 1c1d1e1f 20212223 24252627",
		plaintext:  "11223344 55667788 99aabbcc ddee",
		tag:        "85632d07 c6e8f37f 950acd32 0a2ecc93",
		ciphertext: "40c02b96 90c4dc04 daef7f6a fe5c",
	},
	{
		name:  "rfc5297_nonce_multi_ad",
		key:   "7f7e7d7c 7b7a7978 77767574 73727170 40414243 44454647 48494a4b 4c4d4e4f",
		nonce: "09f91102 9d74e35b d84156c5 635688c0",
		ad: []string{
			"00112233 44556677 8899aabb ccddeeff deaddada deaddada ffeeddcc bbaa9988 77665544 33221100",
			"10203040 50607080 90a0",
		},
		plaintext:  "74686973 20697320 736f6d65 20706c61 696e7465 78742074 6f20656e 63727970 74207573 696e6720 5349562d 414553",
		tag:        "7bdb6e3b 432667eb 06f4d14b ff2fbd0f",
		ciphertext: "cb900f2f ddbe4043 26601965 c889bf17 dba77ceb 094fa663 b7a3f748 ba8af829 ea64ad54 4a272e9c 485b62a3 fd5c0d",
		useMulti:   true,
	},
}

func decodeSpacedHex(t *testing.T, s string) []byte {
	t.Helper()
	clean := strings.NewReplacer(" ", "", "\n", "", "\t", "").Replace(s)
	if clean == "" {
		return nil
	}
	return testutil.MustHex(t, clean)
}

func TestAESSIV_KnownVectors(t *testing.T) {
	cipher := aead.NewAES128SIV()

	multi, hasMulti := cipher.(aead.MultiAssociatedData)

	for _, tc := range aesSIVVectors {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			key := decodeSpacedHex(t, tc.key)
			nonce := decodeSpacedHex(t, tc.nonce)
			plaintext := decodeSpacedHex(t, tc.plaintext)
			tag := decodeSpacedHex(t, tc.tag)
			ciphertext := decodeSpacedHex(t, tc.ciphertext)
			expected := append(append([]byte(nil), ciphertext...), tag...)

			switch {
			case tc.useMulti:
				if !hasMulti {
					t.Fatalf("aesSIV does not implement multi-associated-data interface")
				}
				var associated [][]byte
				for _, ad := range tc.ad {
					associated = append(associated, decodeSpacedHex(t, ad))
				}

				got, err := multi.EncryptWithAssociatedData(key, nonce, associated, plaintext)
				if err != nil {
					t.Fatalf("encrypt failed: %v", err)
				}
				if !bytes.Equal(got, expected) {
					t.Fatalf("encrypt mismatch:\n got %x\nwant %x", got, expected)
				}

				dec, err := multi.DecryptWithAssociatedData(key, nonce, associated, expected)
				if err != nil {
					t.Fatalf("decrypt failed: %v", err)
				}
				if !bytes.Equal(dec, plaintext) {
					t.Fatalf("decrypt mismatch:\n got %x\nwant %x", dec, plaintext)
				}
			default:
				ad := decodeSpacedHex(t, tc.singleAD)
				got, err := cipher.Encrypt(key, nonce, ad, plaintext)
				if err != nil {
					t.Fatalf("encrypt failed: %v", err)
				}
				if !bytes.Equal(got, expected) {
					t.Fatalf("encrypt mismatch:\n got %x\nwant %x", got, expected)
				}
				dec, err := cipher.Decrypt(key, nonce, ad, expected)
				if err != nil {
					t.Fatalf("decrypt failed: %v", err)
				}
				if !bytes.Equal(dec, plaintext) {
					t.Fatalf("decrypt mismatch:\n got %x\nwant %x", dec, plaintext)
				}
			}
		})
	}
}

func TestAESSIV_TagTamper(t *testing.T) {
	cipher := aead.NewAES128SIV()
	key := make([]byte, 32)
	nonce := []byte("nonce")
	ad := []byte("associated")
	pt := []byte("secret message")

	ct, err := cipher.Encrypt(key, nonce, ad, pt)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	tampered := append([]byte(nil), ct...)
	tampered[len(tampered)-1] ^= 0x01

	if _, err := cipher.Decrypt(key, nonce, ad, tampered); err == nil {
		t.Fatalf("decrypt succeeded on tampered tag")
	}
}
