package sig_test

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"os"
	"strconv"
	"strings"
	"testing"

	sig "github.com/AeonDave/cryptonite-go/sig"
)

// DRBG replicates the AES-CTR DRBG used by NIST's PQCgenKAT toolchain.
type drbg struct {
	key [32]byte
	v   [16]byte
}

func (g *drbg) incV() {
	for j := 15; j >= 0; j-- {
		if g.v[j] == 255 {
			g.v[j] = 0
		} else {
			g.v[j]++
			break
		}
	}
}

func (g *drbg) update(pd *[48]byte) {
	var buf [48]byte
	block, _ := aes.NewCipher(g.key[:])
	for i := 0; i < 3; i++ {
		g.incV()
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

func newDRBG(seed *[48]byte) drbg {
	var g drbg
	g.update(seed)
	return g
}

func (g *drbg) fill(out []byte) {
	var block [16]byte
	cipher, _ := aes.NewCipher(g.key[:])
	for len(out) > 0 {
		g.incV()
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

func TestMLDSAKAT(t *testing.T) {
	type katCase struct {
		name        string
		path        string
		keygen      func([]byte) ([]byte, []byte, error)
		signer      func() sig.Signature
		sigLen      int
		publicSize  int
		privateSize int
	}

	cases := []katCase{
		{
			name:        "ML-DSA-44",
			path:        "testdata/PQCsignKAT_ML-DSA-44.rsp",
			keygen:      sig.GenerateDeterministicKeyMLDSA44,
			signer:      sig.NewDeterministicMLDSA44,
			sigLen:      sig.MLDSA44SignatureSize,
			publicSize:  sig.MLDSA44PublicKeySize,
			privateSize: sig.MLDSA44SecretKeySize,
		},
		{
			name:        "ML-DSA-65",
			path:        "testdata/PQCsignKAT_ML-DSA-65.rsp",
			keygen:      sig.GenerateDeterministicKeyMLDSA65,
			signer:      sig.NewDeterministicMLDSA65,
			sigLen:      sig.MLDSA65SignatureSize,
			publicSize:  sig.MLDSA65PublicKeySize,
			privateSize: sig.MLDSA65SecretKeySize,
		},
		{
			name:        "ML-DSA-87",
			path:        "testdata/PQCsignKAT_ML-DSA-87.rsp",
			keygen:      sig.GenerateDeterministicKeyMLDSA87,
			signer:      sig.NewDeterministicMLDSA87,
			sigLen:      sig.MLDSA87SignatureSize,
			publicSize:  sig.MLDSA87PublicKeySize,
			privateSize: sig.MLDSA87SecretKeySize,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			runDilithiumKAT(t, tc)
		})
	}
}

func runDilithiumKAT(t *testing.T, tc struct {
	name        string
	path        string
	keygen      func([]byte) ([]byte, []byte, error)
	signer      func() sig.Signature
	sigLen      int
	publicSize  int
	privateSize int
}) {
	t.Helper()

	file, err := os.Open(tc.path)
	if err != nil {
		t.Fatalf("failed to open %s: %v", tc.path, err)
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	signer := tc.signer()

	var (
		count int
		mlen  int
		smlen int
		msg   []byte
		pub   []byte
		priv  []byte
		seed  [48]byte
	)
	for i := 0; i < len(seed); i++ {
		seed[i] = byte(i)
	}
	generator := newDRBG(&seed)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		parts := strings.Split(line, " ")
		if len(parts) != 3 {
			continue
		}
		raw := strings.TrimSpace(parts[2])
		switch parts[0] {
		case "count":
			count, _ = strconv.Atoi(raw)
		case "seed":
			data, err := hex.DecodeString(raw)
			if err != nil {
				t.Fatalf("failed decoding seed: %v", err)
			}
			if len(data) != len(seed) {
				t.Fatalf("seed length mismatch: got %d, want %d", len(data), len(seed))
			}
			generator.fill(seed[:])
			if !bytes.Equal(seed[:], data) {
				t.Fatalf("kat seed mismatch at vector %d", count)
			}
			drbg := newDRBG(&seed)
			var extSeed [32]byte
			drbg.fill(extSeed[:])
			pub, priv, err = tc.keygen(extSeed[:])
			if err != nil {
				t.Fatalf("keygen failed: %v", err)
			}
			if len(pub) != tc.publicSize || len(priv) != tc.privateSize {
				t.Fatalf("key sizes mismatch: got pk=%d sk=%d", len(pub), len(priv))
			}
		case "mlen":
			mlen, _ = strconv.Atoi(raw)
			if mlen != 33*(count+1) {
				t.Fatalf("mlen does not match expected formula, got %d", mlen)
			}
			msg = make([]byte, mlen)
			generator.fill(msg)
		case "msg":
			data, err := hex.DecodeString(raw)
			if err != nil {
				t.Fatalf("failed decoding msg: %v", err)
			}
			if len(data) != mlen || !bytes.Equal(msg, data) {
				t.Fatalf("message mismatch at vector %d", count)
			}
		case "pk":
			data, err := hex.DecodeString(raw)
			if err != nil {
				t.Fatalf("failed decoding pk: %v", err)
			}
			if len(data) != tc.publicSize {
				t.Fatalf("public key size mismatch: got %d want %d", len(data), tc.publicSize)
			}
			if !bytes.Equal(pub, data) {
				t.Fatalf("public key mismatch at vector %d", count)
			}
		case "sk":
			data, err := hex.DecodeString(raw)
			if err != nil {
				t.Fatalf("failed decoding sk: %v", err)
			}
			if len(data) != tc.privateSize {
				t.Fatalf("secret key size mismatch: got %d want %d", len(data), tc.privateSize)
			}
			if !bytes.Equal(priv, data) {
				t.Fatalf("secret key mismatch at vector %d", count)
			}
		case "smlen":
			smlen, _ = strconv.Atoi(raw)
			if smlen != mlen+tc.sigLen {
				t.Fatalf("signature+message length mismatch: got %d want %d", smlen, mlen+tc.sigLen)
			}
		case "sm":
			data, err := hex.DecodeString(raw)
			if err != nil {
				t.Fatalf("failed decoding sm: %v", err)
			}
			if len(data) != smlen {
				t.Fatalf("sm length mismatch: got %d want %d", len(data), smlen)
			}
			sigPart, err := signer.Sign(priv, msg)
			if err != nil {
				t.Fatalf("sign failed: %v", err)
			}
			if len(sigPart) != tc.sigLen {
				t.Fatalf("signature length mismatch: got %d want %d", len(sigPart), tc.sigLen)
			}
			full := append(append([]byte{}, sigPart...), msg...)
			if !bytes.Equal(full, data) {
				t.Fatalf("signature mismatch at vector %d", count)
			}
			if !signer.Verify(pub, msg, sigPart) {
				t.Fatalf("verification failed at vector %d", count)
			}
		default:
			t.Fatalf("unexpected field %q in kat file", parts[0])
		}
	}
}
