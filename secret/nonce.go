package secret

import (
	"errors"
	"runtime"
	"sync"
)

// ErrNonceExhausted signals that a counter has produced every possible value.
var ErrNonceExhausted = errors.New("secret: nonce space exhausted")

type counter struct {
	mu        sync.Mutex
	value     []byte
	exhausted bool
}

func newCounter(size int, initial []byte) (*counter, error) {
	if len(initial) != size {
		return nil, errors.New("secret: invalid initial nonce size")
	}
	buf := make([]byte, size)
	copy(buf, initial)
	return &counter{value: buf}, nil
}

func (c *counter) next() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.exhausted {
		return nil, ErrNonceExhausted
	}
	out := make([]byte, len(c.value))
	copy(out, c.value)
	if !incrementBE(c.value) {
		c.exhausted = true
	}
	runtime.KeepAlive(c.value)
	return out, nil
}

func (c *counter) preview() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]byte, len(c.value))
	copy(out, c.value)
	runtime.KeepAlive(c.value)
	return out
}

func (c *counter) wipe() {
	c.mu.Lock()
	for i := range c.value {
		c.value[i] = 0
	}
	c.exhausted = true
	runtime.KeepAlive(c.value)
	c.mu.Unlock()
}

// Counter96 manages 96-bit (12-byte) nonces using a monotonically increasing
// counter encoded as big-endian bytes.
type Counter96 struct {
	counter *counter
}

// NewCounter96 constructs a Counter96 initialised to initial.
func NewCounter96(initial []byte) (*Counter96, error) {
	c, err := newCounter(12, initial)
	if err != nil {
		return nil, err
	}
	return &Counter96{counter: c}, nil
}

// Next returns the current nonce value and advances the internal counter.
func (c *Counter96) Next() ([]byte, error) {
	if c == nil || c.counter == nil {
		return nil, errors.New("secret: nil Counter96")
	}
	return c.counter.next()
}

// Peek returns a copy of the next nonce without advancing the counter.
func (c *Counter96) Peek() ([]byte, error) {
	if c == nil || c.counter == nil {
		return nil, errors.New("secret: nil Counter96")
	}
	return c.counter.preview(), nil
}

// Destroy zeroes the counter state and marks it as exhausted.
func (c *Counter96) Destroy() {
	if c == nil || c.counter == nil {
		return
	}
	c.counter.wipe()
}

// Counter192 manages 192-bit (24-byte) nonces.
type Counter192 struct {
	counter *counter
}

// NewCounter192 constructs a Counter192 initialised to initial.
func NewCounter192(initial []byte) (*Counter192, error) {
	c, err := newCounter(24, initial)
	if err != nil {
		return nil, err
	}
	return &Counter192{counter: c}, nil
}

// Next returns the current nonce value and advances the counter.
func (c *Counter192) Next() ([]byte, error) {
	if c == nil || c.counter == nil {
		return nil, errors.New("secret: nil Counter192")
	}
	return c.counter.next()
}

// Peek returns the next nonce without incrementing the counter.
func (c *Counter192) Peek() ([]byte, error) {
	if c == nil || c.counter == nil {
		return nil, errors.New("secret: nil Counter192")
	}
	return c.counter.preview(), nil
}

// Destroy zeroes the counter state and marks it as exhausted.
func (c *Counter192) Destroy() {
	if c == nil || c.counter == nil {
		return
	}
	c.counter.wipe()
}

func incrementBE(buf []byte) bool {
	for i := len(buf) - 1; i >= 0; i-- {
		buf[i]++
		if buf[i] != 0 {
			return true
		}
	}
	return false
}
