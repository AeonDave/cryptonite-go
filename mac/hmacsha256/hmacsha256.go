package hmacsha256

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
)

// Sum computes HMAC-SHA256 over data using key and returns the resulting MAC.
func Sum(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// Verify recomputes HMAC-SHA256 over data and compares it with mac in
// constant time. It returns true if and only if the MACs match.
func Verify(key, data, mac []byte) bool {
	expected := Sum(key, data)
	return subtle.ConstantTimeCompare(expected, mac) == 1
}
