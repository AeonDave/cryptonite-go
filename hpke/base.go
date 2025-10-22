package hpke

import (
	"errors"
	"io"
)

const (
	modeBase byte = 0x00
)

// SenderContext holds the encryption state for the HPKE sender.
type SenderContext struct {
	ctx *hpkeContext
}

// Seal encrypts pt with the provided associated data aad, returning ciphertext
// with the AEAD authentication tag appended.
func (s *SenderContext) Seal(aad, pt []byte) ([]byte, error) {
	if s == nil || s.ctx == nil {
		return nil, errors.New("hpke: nil sender context")
	}
	nonce, err := s.ctx.nextNonce()
	if err != nil {
		return nil, err
	}
	var ct []byte
	err = s.ctx.key.Use(func(key []byte) error {
		var err error
		ct, err = s.ctx.aead.Seal(key, nonce, aad, pt)
		return err
	})
	if err != nil {
		return nil, err
	}
	return ct, nil
}

// Export derives exporter secret material of length outLen using the HPKE
// exporter interface.
func (s *SenderContext) Export(info []byte, outLen int) ([]byte, error) {
	if s == nil || s.ctx == nil {
		return nil, errors.New("hpke: nil sender context")
	}
	return s.ctx.export(info, outLen)
}

// Destroy zeroises every piece of sensitive material associated with the context.
func (s *SenderContext) Destroy() {
	if s == nil {
		return
	}
	s.ctx.destroy()
}

// ReceiverContext holds the decryption state for the HPKE receiver.
type ReceiverContext struct {
	ctx *hpkeContext
}

// Open authenticates and decrypts ct using aad, returning the plaintext.
func (r *ReceiverContext) Open(aad, ct []byte) ([]byte, error) {
	if r == nil || r.ctx == nil {
		return nil, errors.New("hpke: nil receiver context")
	}
	nonce, err := r.ctx.nextNonce()
	if err != nil {
		return nil, err
	}
	var pt []byte
	err = r.ctx.key.Use(func(key []byte) error {
		var err error
		pt, err = r.ctx.aead.Open(key, nonce, aad, ct)
		return err
	})
	if err != nil {
		return nil, err
	}
	return pt, nil
}

// Export derives exporter secret material on the receiver side.
func (r *ReceiverContext) Export(info []byte, outLen int) ([]byte, error) {
	if r == nil || r.ctx == nil {
		return nil, errors.New("hpke: nil receiver context")
	}
	return r.ctx.export(info, outLen)
}

// Destroy wipes all sensitive state associated with the context.
func (r *ReceiverContext) Destroy() {
	if r == nil {
		return
	}
	r.ctx.destroy()
}

// SetupBaseSender performs the HPKE base mode sender setup. It returns the
// encapsulated key (enc) and a ready-to-use sender context.
func SetupBaseSender(rand io.Reader, suite Suite, recipientPublicKey, info []byte) ([]byte, *SenderContext, error) {
	cs, err := newCipherSuite(suite)
	if err != nil {
		return nil, nil, err
	}
	enc, sharedSecret, err := cs.encapsulate(rand, recipientPublicKey)
	if err != nil {
		return nil, nil, err
	}
	ctx, err := cs.keySchedule(modeBase, sharedSecret, info)
	if err != nil {
		return nil, nil, err
	}
	return enc, &SenderContext{ctx: ctx}, nil
}

// SetupBaseReceiver performs the HPKE base mode receiver setup using the
// encapsulated key enc and the recipient private key material.
func SetupBaseReceiver(suite Suite, enc, recipientPrivateKey, info []byte) (*ReceiverContext, error) {
	cs, err := newCipherSuite(suite)
	if err != nil {
		return nil, err
	}
	sharedSecret, err := cs.decapsulate(enc, recipientPrivateKey)
	if err != nil {
		return nil, err
	}
	ctx, err := cs.keySchedule(modeBase, sharedSecret, info)
	if err != nil {
		return nil, err
	}
	return &ReceiverContext{ctx: ctx}, nil
}
