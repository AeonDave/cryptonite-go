package kdf

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
)

// PBKDF2SHA1 derives key material using PBKDF2-HMAC-SHA1 (RFC 2898).
func PBKDF2SHA1(password, salt []byte, iterations, keyLen int) ([]byte, error) {
	return pbkdf2(password, salt, iterations, keyLen, sha1.New)
}

// PBKDF2SHA256 derives key material using PBKDF2-HMAC-SHA256.
func PBKDF2SHA256(password, salt []byte, iterations, keyLen int) ([]byte, error) {
	return pbkdf2(password, salt, iterations, keyLen, sha256.New)
}

func pbkdf2(password, salt []byte, iterations, keyLen int, newHash func() hash.Hash) ([]byte, error) {
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
	output := make([]byte, n*hLen)
	var blockBuf = make([]byte, len(salt)+4)
	copy(blockBuf, salt)
	for block := 1; block <= n; block++ {
		binary.BigEndian.PutUint32(blockBuf[len(salt):], uint32(block))
		mac := hmac.New(newHash, password)
		mac.Write(blockBuf)
		u := mac.Sum(nil)
		t := make([]byte, len(u))
		copy(t, u)
		for i := 1; i < iterations; i++ {
			mac.Reset()
			mac.Write(u)
			u = mac.Sum(u[:0])
			for j := 0; j < len(t); j++ {
				t[j] ^= u[j]
			}
		}
		copy(output[(block-1)*hLen:], t)
	}
	return output[:keyLen], nil
}
