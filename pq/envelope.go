package pq

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/AeonDave/cryptonite-go/aead"
	"github.com/AeonDave/cryptonite-go/kdf"
	"github.com/AeonDave/cryptonite-go/kem"
	"github.com/AeonDave/cryptonite-go/secret"
)

const (
	envelopeVersion byte = 0x01
)

var (
	errNilKEM        = errors.New("pq: nil KEM")
	errNilAEAD       = errors.New("pq: nil AEAD")
	errInvalidBlob   = errors.New("pq: invalid envelope blob")
	errFormatVersion = errors.New("pq: unsupported envelope version")
	errNoSchedule    = errors.New("pq: unable to derive AEAD parameters")
)

type envelopeSchedule struct {
	keyLen        int
	nonceLen      int
	nonceOptional bool
}

var envelopeSchedules = []envelopeSchedule{
	{keyLen: 32, nonceLen: 12},                     // ChaCha20-Poly1305, AES-256-GCM, AES-GCM-SIV (32)
	{keyLen: 32, nonceLen: 16},                     // Ascon-128a, Deoxys-II, Xoodyak
	{keyLen: 32, nonceLen: 24},                     // XChaCha20-Poly1305
	{keyLen: 16, nonceLen: 12},                     // AES-128-GCM
	{keyLen: 16, nonceLen: 16},                     // Future 128-bit AEADs with 128-bit nonce
	{keyLen: 24, nonceLen: 12},                     // AES-192-GCM
	{keyLen: 32, nonceLen: 0, nonceOptional: true}, // AES-128-SIV (nonce optional)
	{keyLen: 64, nonceLen: 0, nonceOptional: true}, // AES-256-SIV (nonce optional)
	{keyLen: 64, nonceLen: 16},                     // AES-256-SIV with explicit nonce input
}

// Seal performs KEM -> HKDF -> AEAD composition using the provided KEM and
// AEAD implementations. The returned blob encodes the encapsulated key, the
// chosen key schedule identifier, and the AEAD ciphertext (ciphertext || tag).
func Seal(k kem.KEM, cipher aead.Aead, publicKey, associatedData, plaintext []byte) ([]byte, error) {
	if k == nil {
		return nil, errNilKEM
	}
	if cipher == nil {
		return nil, errNilAEAD
	}
	enc, sharedSecret, err := k.Encapsulate(publicKey)
	if err != nil {
		return nil, err
	}
	if len(enc) > 0xFFFF {
		secret.WipeBytes(sharedSecret)
		return nil, fmt.Errorf("pq: KEM ciphertext too large: %d", len(enc))
	}
	scheduleID, key, nonce, ct, err := envelopeEncrypt(cipher, sharedSecret, associatedData, plaintext)
	secret.WipeBytes(sharedSecret)
	if err != nil {
		return nil, err
	}
	blob := make([]byte, 1+2+len(enc)+1+len(ct))
	blob[0] = envelopeVersion
	binary.BigEndian.PutUint16(blob[1:3], uint16(len(enc)))
	copy(blob[3:], enc)
	blob[3+len(enc)] = scheduleID
	copy(blob[4+len(enc):], ct)
	secret.WipeBytes(key)
	secret.WipeBytes(nonce)
	secret.WipeBytes(ct)
	return blob, nil
}

func envelopeEncrypt(cipher aead.Aead, sharedSecret, ad, pt []byte) (byte, []byte, []byte, []byte, error) {
	for id, schedule := range envelopeSchedules {
		key, err := deriveEnvelopeMaterial(sharedSecret, byte(id), 'k', schedule.keyLen)
		if err != nil {
			return 0, nil, nil, nil, err
		}
		var nonce []byte
		if schedule.nonceLen > 0 {
			nonce, err = deriveEnvelopeMaterial(sharedSecret, byte(id), 'n', schedule.nonceLen)
			if err != nil {
				secret.WipeBytes(key)
				return 0, nil, nil, nil, err
			}
		}
		if schedule.nonceLen == 0 && schedule.nonceOptional {
			nonce = nil
		}
		ct, err := cipher.Encrypt(key, nonce, ad, pt)
		if err != nil {
			if shouldRetryEnvelope(err) {
				secret.WipeBytes(key)
				secret.WipeBytes(nonce)
				continue
			}
			secret.WipeBytes(key)
			secret.WipeBytes(nonce)
			return 0, nil, nil, nil, err
		}
		return byte(id), key, nonce, ct, nil
	}
	return 0, nil, nil, nil, errNoSchedule
}

// Open reverses Seal by decapsulating the shared secret and decrypting the
// payload using the stored key schedule identifier.
func Open(k kem.KEM, cipher aead.Aead, privateKey, associatedData, blob []byte) ([]byte, error) {
	if k == nil {
		return nil, errNilKEM
	}
	if cipher == nil {
		return nil, errNilAEAD
	}
	if len(blob) < 4 {
		return nil, errInvalidBlob
	}
	if blob[0] != envelopeVersion {
		return nil, errFormatVersion
	}
	kemLen := int(binary.BigEndian.Uint16(blob[1:3]))
	offset := 3
	if kemLen < 0 || len(blob) < offset+kemLen+1 {
		return nil, errInvalidBlob
	}
	enc := blob[offset : offset+kemLen]
	offset += kemLen
	scheduleID := blob[offset]
	offset++
	if int(scheduleID) >= len(envelopeSchedules) {
		return nil, errInvalidBlob
	}
	ciphertext := blob[offset:]
	sharedSecret, err := k.Decapsulate(privateKey, enc)
	if err != nil {
		return nil, err
	}
	schedule := envelopeSchedules[int(scheduleID)]
	key, derr := deriveEnvelopeMaterial(sharedSecret, scheduleID, 'k', schedule.keyLen)
	if derr != nil {
		secret.WipeBytes(sharedSecret)
		return nil, derr
	}
	var nonce []byte
	if schedule.nonceLen > 0 {
		nonce, derr = deriveEnvelopeMaterial(sharedSecret, scheduleID, 'n', schedule.nonceLen)
		if derr != nil {
			secret.WipeBytes(sharedSecret)
			secret.WipeBytes(key)
			return nil, derr
		}
	}
	if schedule.nonceLen == 0 && schedule.nonceOptional {
		nonce = nil
	}
	plaintext, derr := cipher.Decrypt(key, nonce, associatedData, ciphertext)
	secret.WipeBytes(sharedSecret)
	secret.WipeBytes(key)
	secret.WipeBytes(nonce)
	if derr != nil {
		return nil, derr
	}
	return plaintext, nil
}

func deriveEnvelopeMaterial(shared []byte, scheduleID byte, domain byte, length int) ([]byte, error) {
	if length == 0 {
		return nil, nil
	}
	info := []byte("cryptonite-go/pq/envelope/")
	info = append(info, domain)
	info = append(info, scheduleID)
	return kdf.HKDFSHA256(shared, nil, info, length)
}

func shouldRetryEnvelope(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "invalid key size") || strings.Contains(msg, "invalid nonce size")
}
