package kdf

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
)

type pbkdf2SHA1Deriver struct{}
type pbkdf2SHA256Deriver struct{}

var (
	errIterationsTooLow = errors.New("pbkdf2: iterations below minimum")
	errSaltTooShort     = errors.New("pbkdf2: salt shorter than minimum")
)

// NewPBKDF2SHA1 returns a Deriver instance backed by PBKDF2-HMAC-SHA1 (RFC 2898).
func NewPBKDF2SHA1() Deriver { return pbkdf2SHA1Deriver{} }

// NewPBKDF2SHA256 returns a Deriver instance backed by PBKDF2-HMAC-SHA256.
func NewPBKDF2SHA256() Deriver { return pbkdf2SHA256Deriver{} }

func (pbkdf2SHA1Deriver) Derive(params DeriveParams) ([]byte, error) {
	return pbkdf2(params.Secret, params.Salt, params.Iterations, params.Length, sha1.New)
}

func (pbkdf2SHA256Deriver) Derive(params DeriveParams) ([]byte, error) {
	return pbkdf2(params.Secret, params.Salt, params.Iterations, params.Length, sha256.New)
}

// PBKDF2SHA1 derives key material using PBKDF2-HMAC-SHA1 (RFC 2898).
func PBKDF2SHA1(password, salt []byte, iterations, keyLen int) ([]byte, error) {
	return pbkdf2(password, salt, iterations, keyLen, sha1.New)
}

// PBKDF2SHA256 derives key material using PBKDF2-HMAC-SHA256.
func PBKDF2SHA256(password, salt []byte, iterations, keyLen int) ([]byte, error) {
	return pbkdf2(password, salt, iterations, keyLen, sha256.New)
}

// PBKDF2SHA1Into derives key material into dst using PBKDF2-HMAC-SHA1.
func PBKDF2SHA1Into(password, salt []byte, iterations int, dst []byte) ([]byte, error) {
	return pbkdf2Into(password, salt, iterations, len(dst), dst, sha1.New)
}

// PBKDF2SHA256Into derives key material into dst using PBKDF2-HMAC-SHA256.
func PBKDF2SHA256Into(password, salt []byte, iterations int, dst []byte) ([]byte, error) {
	return pbkdf2Into(password, salt, iterations, len(dst), dst, sha256.New)
}

// CheckParams validates PBKDF2 derivation parameters against the supplied minimums.
func CheckParams(params DeriveParams, minIter, minSalt int) error {
	if params.Iterations < minIter {
		return errIterationsTooLow
	}
	if len(params.Salt) < minSalt {
		return errSaltTooShort
	}
	if params.Length <= 0 {
		return errors.New("pbkdf2: invalid key length")
	}
	return nil
}

func pbkdf2(password, salt []byte, iterations, keyLen int, newHash func() hash.Hash) ([]byte, error) {
	return pbkdf2Into(password, salt, iterations, keyLen, nil, newHash)
}

func pbkdf2Into(password, salt []byte, iterations, keyLen int, dst []byte, newHash func() hash.Hash) ([]byte, error) {
	if iterations <= 0 {
		return nil, errors.New("pbkdf2: iterations must be > 0")
	}
	if keyLen <= 0 {
		return nil, errors.New("pbkdf2: invalid key length")
	}
	hLen := newHash().Size()
	n := (keyLen + hLen - 1) / hLen
	if n > (1<<32 - 1) {
		return nil, errors.New("pbkdf2: derived key too large")
	}
	var output []byte
	if dst == nil {
		output = make([]byte, keyLen)
	} else {
		if len(dst) < keyLen {
			return nil, errors.New("pbkdf2: destination too short")
		}
		output = dst[:keyLen]
	}
	mac := hmac.New(newHash, password)
	blockBuf := make([]byte, len(salt)+4)
	copy(blockBuf, salt)
	u := make([]byte, hLen)
	t := make([]byte, hLen)
	written := 0
	for block := 1; block <= n; block++ {
		binary.BigEndian.PutUint32(blockBuf[len(salt):], uint32(block))
		mac.Reset()
		mac.Write(blockBuf)
		mac.Sum(u[:0])
		copy(t, u)
		for i := 1; i < iterations; i++ {
			mac.Reset()
			mac.Write(u)
			mac.Sum(u[:0])
			for j := 0; j < hLen; j++ {
				t[j] ^= u[j]
			}
		}
		copyLen := hLen
		if remaining := keyLen - written; remaining < copyLen {
			copyLen = remaining
		}
		copy(output[written:], t[:copyLen])
		written += copyLen
	}
	return output, nil
}
