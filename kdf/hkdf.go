package kdf

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	stdhash "hash"

	"github.com/AeonDave/cryptonite-go/internal/blake2b"
)

const (
	hkdfSHA256MaxLen = 255 * sha256.Size
	hkdfMaxBlocks    = 255
)

type (
	hkdfSHA256Deriver  struct{}
	hkdfGenericDeriver struct {
		newHash func() stdhash.Hash
	}
)

// NewHKDFSHA256 returns a Deriver instance that computes HKDF-SHA256 (RFC 5869).
func NewHKDFSHA256() Deriver { return hkdfSHA256Deriver{} }

// NewHKDF constructs a Deriver backed by the provided hash constructor.
func NewHKDF(newHash func() stdhash.Hash) Deriver { return hkdfGenericDeriver{newHash: newHash} }

// NewHKDFBlake2b returns a Deriver that computes HKDF using BLAKE2b as the underlying hash.
func NewHKDFBlake2b() Deriver { return hkdfGenericDeriver{newHash: newBlake2bHash} }

// Derive derives key material of length params.Length using HKDF with SHA-256.
func (hkdfSHA256Deriver) Derive(params DeriveParams) ([]byte, error) {
	return HKDFSHA256(params.Secret, params.Salt, params.Info, params.Length)
}

// Derive derives key material using the configured hash constructor.
func (d hkdfGenericDeriver) Derive(params DeriveParams) ([]byte, error) {
	return HKDF(d.newHash, params.Secret, params.Salt, params.Info, params.Length)
}

// HKDFSHA256 derives key material of length outLen using HKDF (RFC 5869) with SHA-256.
func HKDFSHA256(ikm, salt, info []byte, outLen int) ([]byte, error) {
	if outLen <= 0 {
		return nil, errors.New("hkdf: invalid output length")
	}
	if outLen > hkdfSHA256MaxLen {
		return nil, errors.New("hkdf: length too large for SHA-256")
	}
	prk := HKDFExtractWith(sha256.New, salt, ikm)
	return HKDFExpandWith(sha256.New, prk, info, outLen)
}

// HKDF derives key material of length outLen using HKDF with the provided hash.
func HKDF(newHash func() stdhash.Hash, ikm, salt, info []byte, outLen int) ([]byte, error) {
	if outLen <= 0 {
		return nil, errors.New("hkdf: invalid output length")
	}
	h := newHash()
	if h == nil {
		return nil, errors.New("hkdf: nil hash constructor")
	}
	maxLen := hkdfMaxBlocks * h.Size()
	if outLen > maxLen {
		return nil, errors.New("hkdf: length too large for hash")
	}
	prk := HKDFExtractWith(newHash, salt, ikm)
	return HKDFExpandWith(newHash, prk, info, outLen)
}

// HKDFBlake2b derives key material using HKDF with BLAKE2b (64-byte digest).
func HKDFBlake2b(ikm, salt, info []byte, outLen int) ([]byte, error) {
	return HKDF(newBlake2bHash, ikm, salt, info, outLen)
}

// HKDFSHA256Extract returns the pseudorandom key (PRK) for HKDF-SHA256.
func HKDFSHA256Extract(salt, ikm []byte) []byte {
	return HKDFExtractWith(sha256.New, salt, ikm)
}

// HKDFSHA256Expand derives key material from the PRK for HKDF-SHA256.
func HKDFSHA256Expand(prk, info []byte, outLen int) ([]byte, error) {
	if outLen <= 0 {
		return nil, errors.New("hkdf: invalid output length")
	}
	if outLen > hkdfSHA256MaxLen {
		return nil, errors.New("hkdf: length too large for SHA-256")
	}
	return HKDFExpandWith(sha256.New, prk, info, outLen)
}

// HKDFExtractWith returns the pseudorandom key (PRK) for the supplied hash constructor.
func HKDFExtractWith(newHash func() stdhash.Hash, salt, ikm []byte) []byte {
	h := newHash()
	if salt == nil || len(salt) == 0 {
		salt = make([]byte, h.Size())
	}
	mac := hmac.New(newHash, salt)
	mac.Write(ikm)
	return mac.Sum(nil)
}

// HKDFExpandWith derives key material from the PRK for the provided hash constructor.
func HKDFExpandWith(newHash func() stdhash.Hash, prk, info []byte, length int) ([]byte, error) {
	hLen := newHash().Size()
	n := (length + hLen - 1) / hLen
	if n > hkdfMaxBlocks {
		return nil, errors.New("hkdf: too many blocks")
	}
	out := make([]byte, length)
	mac := hmac.New(newHash, prk)
	var t []byte
	written := 0
	for i := 1; i <= n; i++ {
		mac.Reset()
		mac.Write(t)
		mac.Write(info)
		mac.Write([]byte{byte(i)})
		t = mac.Sum(t[:0])
		copyLen := hLen
		if remaining := length - written; remaining < copyLen {
			copyLen = remaining
		}
		copy(out[written:], t[:copyLen])
		written += copyLen
	}
	return out, nil
}

func newBlake2bHash() stdhash.Hash {
	h, err := blake2b.New(blake2b.Size, nil)
	if err != nil {
		panic(err)
	}
	return h
}
