package hpke_test

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/AeonDave/cryptonite-go/hpke"
)

//go:embed testdata/base_vectors.json
var baseVectorsJSON []byte

type hpkeVector struct {
	Suite        hpke.Suite `json:"suite"`
	Seed         string     `json:"seed"`
	RecipientSK  string     `json:"skR"`
	RecipientPK  string     `json:"pkR"`
	Enc          string     `json:"enc"`
	Info         string     `json:"info"`
	AAD          string     `json:"aad"`
	Plaintext    string     `json:"pt"`
	Ciphertext   string     `json:"ct"`
	ExporterInfo string     `json:"exporter_info"`
	ExporterLen  int        `json:"exporter_len"`
	Exporter     string     `json:"exporter"`
}

func TestHPKEBaseVectors(t *testing.T) {
	var vectors []hpkeVector
	if err := json.Unmarshal(baseVectorsJSON, &vectors); err != nil {
		t.Fatalf("failed to parse vectors: %v", err)
	}
	for idx, vec := range vectors {
		seed := mustHex(t, vec.Seed)
		info := mustHex(t, vec.Info)
		aad := mustHex(t, vec.AAD)
		pt := mustHex(t, vec.Plaintext)
		exporterInfo := mustHex(t, vec.ExporterInfo)

		pkR := mustHex(t, vec.RecipientPK)
		skR := mustHex(t, vec.RecipientSK)

		reader := newDeterministicReader(seed)
		enc, sender, err := hpke.SetupBaseSender(reader, vec.Suite, pkR, info)
		if err != nil {
			t.Fatalf("vector %d: SetupBaseSender failed: %v", idx, err)
		}
		ct, err := sender.Seal(aad, pt)
		if err != nil {
			t.Fatalf("vector %d: Seal failed: %v", idx, err)
		}
		exporter, err := sender.Export(exporterInfo, vec.ExporterLen)
		if err != nil {
			t.Fatalf("vector %d: Export failed: %v", idx, err)
		}
		if len(exporter) != vec.ExporterLen {
			t.Fatalf("vector %d: unexpected exporter length: got %d want %d", idx, len(exporter), vec.ExporterLen)
		}
		sender.Destroy()

		receiver, err := hpke.SetupBaseReceiver(vec.Suite, enc, skR, info)
		if err != nil {
			t.Fatalf("vector %d: SetupBaseReceiver failed: %v", idx, err)
		}
		opened, err := receiver.Open(aad, ct)
		if err != nil {
			t.Fatalf("vector %d: Open failed: %v", idx, err)
		}
		if !bytesEqual(opened, pt) {
			t.Fatalf("vector %d: plaintext mismatch\n got %x\nwant %x", idx, opened, pt)
		}
		// Exporter parity between sender and receiver
		expR, err := receiver.Export(exporterInfo, vec.ExporterLen)
		if err != nil {
			t.Fatalf("vector %d: receiver Export failed: %v", idx, err)
		}
		if !bytesEqual(expR, exporter) {
			t.Fatalf("vector %d: exporter secret mismatch between sides", idx)
		}
		receiver.Destroy()
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("failed to decode %q: %v", s, err)
	}
	return b
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

type deterministicReader struct {
	buf []byte
}

func newDeterministicReader(seed []byte) *deterministicReader {
	dup := make([]byte, len(seed))
	copy(dup, seed)
	return &deterministicReader{buf: dup}
}

func (r *deterministicReader) Read(p []byte) (int, error) {
	if len(r.buf) == 0 {
		return 0, errors.New("deterministic reader exhausted")
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}
