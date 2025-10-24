package pq_test

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	internalKyber "github.com/AeonDave/cryptonite-go/internal/kyber"
	"github.com/AeonDave/cryptonite-go/kem"
	"github.com/AeonDave/cryptonite-go/pq"
)

type ctrDRBG struct {
	key [32]byte
	v   [16]byte
}

func newCTRDRBG(seed []byte) *ctrDRBG {
	var init [48]byte
	copy(init[:], seed)
	g := &ctrDRBG{}
	g.update(&init)
	return g
}

func (g *ctrDRBG) increment() {
	for i := len(g.v) - 1; i >= 0; i-- {
		g.v[i]++
		if g.v[i] != 0 {
			break
		}
	}
}

func (g *ctrDRBG) update(pd *[48]byte) {
	var buf [48]byte
	block, _ := aes.NewCipher(g.key[:])
	for i := 0; i < 3; i++ {
		g.increment()
		block.Encrypt(buf[i*16:(i+1)*16], g.v[:])
	}
	if pd != nil {
		for i := 0; i < len(buf); i++ {
			buf[i] ^= pd[i]
		}
	}
	copy(g.key[:], buf[:32])
	copy(g.v[:], buf[32:])
}

func (g *ctrDRBG) fill(out []byte) {
	var block [16]byte
	cipher, _ := aes.NewCipher(g.key[:])
	for len(out) > 0 {
		g.increment()
		cipher.Encrypt(block[:], g.v[:])
		if len(out) < len(block) {
			copy(out, block[:len(out)])
			break
		}
		copy(out, block[:])
		out = out[len(block):]
	}
	g.update(nil)
}

func TestMLKEMKAT(t *testing.T) {
	t.Parallel()

	type katCase struct {
		name       string
		file       string
		scheme     *internalKyber.Kyber
		newKEM     func() kem.KEM
		publicLen  int
		privateLen int
		cipherLen  int
	}

	cases := []katCase{
		{
			name:       "ML-KEM-512",
			file:       "testdata/PQCkemKAT_ML-KEM-512.rsp",
			scheme:     internalKyber.NewKyber512(),
			newKEM:     pq.NewMLKEM512,
			publicLen:  internalKyber.Kyber512SizePK,
			privateLen: internalKyber.Kyber512SizeSK,
			cipherLen:  internalKyber.Kyber512SizeC,
		},
		{
			name:       "ML-KEM-768",
			file:       "testdata/PQCkemKAT_ML-KEM-768.rsp",
			scheme:     internalKyber.NewKyber768(),
			newKEM:     pq.NewMLKEM768,
			publicLen:  internalKyber.Kyber768SizePK,
			privateLen: internalKyber.Kyber768SizeSK,
			cipherLen:  internalKyber.Kyber768SizeC,
		},
		{
			name:       "ML-KEM-1024",
			file:       "testdata/PQCkemKAT_ML-KEM-1024.rsp",
			scheme:     internalKyber.NewKyber1024(),
			newKEM:     pq.NewMLKEM1024,
			publicLen:  internalKyber.Kyber1024SizePK,
			privateLen: internalKyber.Kyber1024SizeSK,
			cipherLen:  internalKyber.Kyber1024SizeC,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f, err := os.Open(tc.file)
			if err != nil {
				t.Fatalf("open kat: %v", err)
			}
			defer func(f *os.File) {
				_ = f.Close()
			}(f)

			reader := bufio.NewScanner(f)
			reader.Split(bufio.ScanLines)

			var (
				kseed   []byte
				coins   []byte
				pkBytes []byte
				skBytes []byte
				ctBytes []byte
				ssBytes []byte
				genPK   []byte
				genSK   []byte
				genCT   []byte
				genSS   []byte
			)

			kemInstance := tc.newKEM()

			for reader.Scan() {
				line := strings.TrimSpace(reader.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				parts := strings.SplitN(line, "=", 2)
				if len(parts) != 2 {
					continue
				}
				key := strings.TrimSpace(parts[0])
				val := strings.TrimSpace(parts[1])
				switch key {
				case "count":
					// reset per vector
					kseed = nil
					coins = nil
					pkBytes = nil
					skBytes = nil
					ctBytes = nil
					ssBytes = nil
					genPK = nil
					genSK = nil
					genCT = nil
					genSS = nil
				case "seed":
					seed := mustDecodeHex(t, val, 48)
					drbg := newCTRDRBG(seed)
					kseed = make([]byte, 64)
					drbg.fill(kseed[:32])
					drbg.fill(kseed[32:])
					coins = make([]byte, 32)
					drbg.fill(coins)
					genPK, genSK = tc.scheme.KeyGen(kseed)
				case "pk":
					pkBytes = mustDecodeHex(t, val, tc.publicLen)
					if !bytes.Equal(genPK, pkBytes) {
						t.Fatalf("public key mismatch")
					}
				case "sk":
					skBytes = mustDecodeHex(t, val, tc.privateLen)
					if !bytes.Equal(genSK, skBytes) {
						t.Fatalf("secret key mismatch")
					}
				case "ct":
					ctBytes = mustDecodeHex(t, val, tc.cipherLen)
					genCT, genSS = tc.scheme.Encaps(genPK, coins)
					if !bytes.Equal(genCT, ctBytes) {
						t.Fatalf("ciphertext mismatch")
					}
				case "ss":
					ssBytes = mustDecodeHex(t, val, 32)
					if !bytes.Equal(genSS, ssBytes) {
						t.Fatalf("shared secret mismatch")
					}
					if !bytes.Equal(tc.scheme.Decaps(genSK, genCT), ssBytes) {
						t.Fatalf("decapsulation mismatch")
					}
					shared, err := kemInstance.Decapsulate(skBytes, ctBytes)
					if err != nil {
						t.Fatalf("kem decapsulate error: %v", err)
					}
					if !bytes.Equal(shared, ssBytes) {
						t.Fatalf("kem decapsulation mismatch")
					}
				}
			}
			if err := reader.Err(); err != nil {
				t.Fatalf("scan kat: %v", err)
			}
		})
	}
}

func mustDecodeHex(t *testing.T, s string, wantLen int) []byte {
	t.Helper()
	if s == "" {
		return nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	if wantLen > 0 && len(b) != wantLen {
		t.Fatalf("length mismatch: got %d want %d", len(b), wantLen)
	}
	return b
}
