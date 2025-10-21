package stream

import (
	"cryptonite-go/stream/chacha20"
	"cryptonite-go/stream/xchacha20"
)

var (
	_ Stream = (*chacha20.Cipher)(nil)
	_ Stream = (*xchacha20.Cipher)(nil)
)

// NewChaCha20 returns a ChaCha20 stream cipher implementing Stream.
func NewChaCha20(key, nonce []byte, counter uint32) (Stream, error) {
	return chacha20.New(key, nonce, counter)
}

// NewXChaCha20 returns an XChaCha20 stream cipher implementing Stream.
func NewXChaCha20(key, nonce []byte, counter uint32) (Stream, error) {
	return xchacha20.New(key, nonce, counter)
}
