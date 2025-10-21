package kdf

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"hash"
)

const hkdfSHA256MaxLen = 255 * sha256.Size

// HKDFSHA256 derives key material of length outLen using HKDF (RFC 5869) with SHA-256.
func HKDFSHA256(ikm, salt, info []byte, outLen int) ([]byte, error) {
	if outLen <= 0 {
		return nil, errors.New("hkdf: invalid output length")
	}
	if outLen > hkdfSHA256MaxLen {
		return nil, errors.New("hkdf: length too large for SHA-256")
	}
	prk := hkdfExtract(sha256.New, salt, ikm)
	return hkdfExpand(sha256.New, prk, info, outLen)
}

// HKDFSHA256Extract returns the pseudorandom key (PRK) for HKDF-SHA256.
func HKDFSHA256Extract(salt, ikm []byte) []byte {
	return hkdfExtract(sha256.New, salt, ikm)
}

// HKDFSHA256Expand derives key material from the PRK for HKDF-SHA256.
func HKDFSHA256Expand(prk, info []byte, outLen int) ([]byte, error) {
	if outLen <= 0 {
		return nil, errors.New("hkdf: invalid output length")
	}
	if outLen > hkdfSHA256MaxLen {
		return nil, errors.New("hkdf: length too large for SHA-256")
	}
	return hkdfExpand(sha256.New, prk, info, outLen)
}

func hkdfExtract(newHash func() hash.Hash, salt, ikm []byte) []byte {
	h := newHash()
	if salt == nil || len(salt) == 0 {
		salt = make([]byte, h.Size())
	}
	mac := hmac.New(newHash, salt)
	mac.Write(ikm)
	return mac.Sum(nil)
}

func hkdfExpand(newHash func() hash.Hash, prk, info []byte, length int) ([]byte, error) {
	hLen := newHash().Size()
	n := (length + hLen - 1) / hLen
	if n > 255 {
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
