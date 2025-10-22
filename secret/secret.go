package secret

import (
	"errors"
	"runtime"
	"sync"
)

// ErrDestroyed is returned when operations are attempted on a wiped object.
var ErrDestroyed = errors.New("secret: material destroyed")

type secureBytes struct {
	mu        sync.RWMutex
	data      []byte
	destroyed bool
}

func newSecureBytes(size int) secureBytes {
	buf := make([]byte, size)
	return secureBytes{data: buf}
}

func secureBytesFrom(src []byte) secureBytes {
	dup := make([]byte, len(src))
	copy(dup, src)
	return secureBytes{data: dup}
}

func (s *secureBytes) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.data)
}

func (s *secureBytes) clone() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.destroyed {
		return nil, ErrDestroyed
	}
	out := make([]byte, len(s.data))
	copy(out, s.data)
	runtime.KeepAlive(s.data)
	return out, nil
}

func (s *secureBytes) use(fn func([]byte) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.destroyed {
		return ErrDestroyed
	}
	if err := fn(s.data); err != nil {
		runtime.KeepAlive(s.data)
		return err
	}
	runtime.KeepAlive(s.data)
	return nil
}

func (s *secureBytes) wipe() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.data {
		s.data[i] = 0
	}
	s.destroyed = true
	runtime.KeepAlive(s.data)
}

// SymmetricKey represents key material that is automatically wiped when
// Destroy is invoked. It provides controlled access to the underlying bytes
// and ensures best-effort zeroization.
type SymmetricKey struct {
	inner secureBytes
}

// NewSymmetricKey returns a zeroed symmetric key of the requested size.
func NewSymmetricKey(size int) *SymmetricKey {
	return &SymmetricKey{inner: newSecureBytes(size)}
}

// SymmetricKeyFrom copies src into a new SymmetricKey instance.
func SymmetricKeyFrom(src []byte) *SymmetricKey {
	return &SymmetricKey{inner: secureBytesFrom(src)}
}

// Len reports the size of the key material in bytes.
func (k *SymmetricKey) Len() int {
	if k == nil {
		return 0
	}
	return k.inner.Len()
}

// Bytes returns a copy of the key material.
func (k *SymmetricKey) Bytes() ([]byte, error) {
	if k == nil {
		return nil, errors.New("secret: nil key")
	}
	return k.inner.clone()
}

// Use exposes the key material to fn while ensuring it remains reachable for
// the duration of the call. The provided slice must not escape the callback.
func (k *SymmetricKey) Use(fn func([]byte) error) error {
	if k == nil {
		return errors.New("secret: nil key")
	}
	return k.inner.use(fn)
}

// Destroy zeros the key material and marks the key as destroyed.
func (k *SymmetricKey) Destroy() {
	if k == nil {
		return
	}
	k.inner.wipe()
}

// Nonce represents nonce or IV material tied to a specific length.
type Nonce struct {
	inner secureBytes
}

// NewNonce returns a zeroed nonce buffer of the requested size.
func NewNonce(size int) *Nonce {
	return &Nonce{inner: newSecureBytes(size)}
}

// NonceFrom copies src into a new Nonce instance.
func NonceFrom(src []byte) *Nonce {
	return &Nonce{inner: secureBytesFrom(src)}
}

// Len reports the length of the nonce in bytes.
func (n *Nonce) Len() int {
	if n == nil {
		return 0
	}
	return n.inner.Len()
}

// Bytes returns a copy of the nonce value.
func (n *Nonce) Bytes() ([]byte, error) {
	if n == nil {
		return nil, errors.New("secret: nil nonce")
	}
	return n.inner.clone()
}

// Use exposes the nonce to fn. The slice must not escape the callback.
func (n *Nonce) Use(fn func([]byte) error) error {
	if n == nil {
		return errors.New("secret: nil nonce")
	}
	return n.inner.use(fn)
}

// Destroy zeros the nonce and marks it as destroyed.
func (n *Nonce) Destroy() {
	if n == nil {
		return
	}
	n.inner.wipe()
}

// CloneBytes returns a deep copy of b. It is a convenience helper for callers
// needing to duplicate sensitive material before mutating it.
func CloneBytes(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	runtime.KeepAlive(b)
	return out
}

// WipeBytes overwrites the content of b with zeros and keeps it alive for the
// duration of the call to reduce the likelihood of compiler optimisations
// removing the zeroisation.
func WipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}
