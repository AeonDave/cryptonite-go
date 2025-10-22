package xof

import "github.com/AeonDave/cryptonite-go/internal/keccak"

const (
	domainCSHAKE byte = 0x04
	domainSHAKE  byte = 0x1f
)

// cshakeXOF implements the extendable-output functionality for cSHAKE128/256.
type cshakeXOF struct {
	sponge keccak.Sponge
	rate   int
	prefix []byte
}

func newCSHAKEXOF(rate int, functionName, customization []byte) *cshakeXOF {
	x := &cshakeXOF{rate: rate}
	if len(functionName) != 0 || len(customization) != 0 {
		prefix := keccak.EncodeString(functionName)
		prefix = append(prefix, keccak.EncodeString(customization)...)
		padded := keccak.Bytepad(prefix, rate)
		x.prefix = make([]byte, len(padded))
		copy(x.prefix, padded)
	}
	x.Reset()
	return x
}

func (x *cshakeXOF) Write(p []byte) (int, error) {
	x.sponge.Absorb(p)
	return len(p), nil
}

func (x *cshakeXOF) Read(out []byte) (int, error) {
	x.sponge.Squeeze(out)
	return len(out), nil
}

func (x *cshakeXOF) Reset() {
	domain := domainCSHAKE
	if len(x.prefix) == 0 {
		domain = domainSHAKE
	}
	x.sponge.Init(x.rate, domain)
	if len(x.prefix) > 0 {
		x.sponge.Absorb(x.prefix)
	}
}

// CSHAKE128 returns a cSHAKE128 extendable-output function configured with the
// provided function name (N) and customization string (S).
func CSHAKE128(functionName, customization []byte) XOF {
	return newCSHAKEXOF(168, cloneBytes(functionName), cloneBytes(customization))
}

// CSHAKE256 returns a cSHAKE256 extendable-output function configured with the
// provided function name (N) and customization string (S).
func CSHAKE256(functionName, customization []byte) XOF {
	return newCSHAKEXOF(136, cloneBytes(functionName), cloneBytes(customization))
}

// SumCSHAKE128 computes the cSHAKE128 digest of msg using the provided function
// name (N) and customization string (S), producing outLen bytes of output.
func SumCSHAKE128(functionName, customization, msg []byte, outLen int) []byte {
	x := newCSHAKEXOF(168, cloneBytes(functionName), cloneBytes(customization))
	_, _ = x.Write(msg)
	out := make([]byte, outLen)
	_, _ = x.Read(out)
	return out
}

// SumCSHAKE256 computes the cSHAKE256 digest of msg using the provided function
// name (N) and customization string (S), producing outLen bytes of output.
func SumCSHAKE256(functionName, customization, msg []byte, outLen int) []byte {
	x := newCSHAKEXOF(136, cloneBytes(functionName), cloneBytes(customization))
	_, _ = x.Write(msg)
	out := make([]byte, outLen)
	_, _ = x.Read(out)
	return out
}

func cloneBytes(in []byte) []byte {
	if len(in) == 0 {
		return nil
	}
	out := make([]byte, len(in))
	copy(out, in)
	return out
}
