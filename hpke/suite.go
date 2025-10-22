package hpke

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
	"io"

	"github.com/AeonDave/cryptonite-go/aead"
	"github.com/AeonDave/cryptonite-go/kdf"
	"github.com/AeonDave/cryptonite-go/secret"
)

// Suite identifies a HPKE cipher suite by its KEM, KDF, and AEAD identifiers.
type Suite struct {
	KEM  uint16
	KDF  uint16
	AEAD uint16
}

const (
	// Supported KEM identifiers.
	KEMDHKEMX25519HKDFSHA256 uint16 = 0x0020

	// Supported KDF identifiers.
	KDFHKDFSHA256 uint16 = 0x0001

	// Supported AEAD identifiers.
	AEADAES128GCM        uint16 = 0x0001
	AEADChaCha20Poly1305 uint16 = 0x0003
)

var (
	// SuiteX25519ChaCha20 defines the HPKE base mode suite (DHKEM(X25519),
	// HKDF-SHA256, ChaCha20-Poly1305).
	SuiteX25519ChaCha20 = Suite{KEM: KEMDHKEMX25519HKDFSHA256, KDF: KDFHKDFSHA256, AEAD: AEADChaCha20Poly1305}

	// SuiteX25519AESGCM defines the HPKE base mode suite (DHKEM(X25519),
	// HKDF-SHA256, AES-128-GCM).
	SuiteX25519AESGCM = Suite{KEM: KEMDHKEMX25519HKDFSHA256, KDF: KDFHKDFSHA256, AEAD: AEADAES128GCM}
)

// ErrUnsupportedSuite is returned when attempting to build a cipher suite that
// is not supported by the current implementation.
var ErrUnsupportedSuite = errors.New("hpke: unsupported cipher suite")

type cipherSuite struct {
	suite     Suite
	suiteID   []byte
	hash      func() hash.Hash
	hashLen   int
	kem       *dhkem
	aead      aeadScheme
	keySize   int
	nonceSize int
}

// newCipherSuite constructs a cipher suite instance if supported.
func newCipherSuite(s Suite) (*cipherSuite, error) {
	if s.KEM != KEMDHKEMX25519HKDFSHA256 || s.KDF != KDFHKDFSHA256 {
		return nil, ErrUnsupportedSuite
	}
	kem := newDHKEMX25519()
	var aeadImpl aeadScheme
	var keySize, nonceSize int
	switch s.AEAD {
	case AEADChaCha20Poly1305:
		aeadImpl = newChaCha20Poly1305Scheme()
		keySize = 32
		nonceSize = 12
	case AEADAES128GCM:
		aeadImpl = newAESGCM128Scheme()
		keySize = 16
		nonceSize = 12
	default:
		return nil, ErrUnsupportedSuite
	}
	return &cipherSuite{
		suite:     s,
		suiteID:   buildSuiteID(s),
		hash:      sha256.New,
		hashLen:   sha256.Size,
		kem:       kem,
		aead:      aeadImpl,
		keySize:   keySize,
		nonceSize: nonceSize,
	}, nil
}

func buildSuiteID(s Suite) []byte {
	buf := make([]byte, 0, 4+2+2+2)
	buf = append(buf, []byte("HPKE")...)
	tmp := make([]byte, 2)
	binary.BigEndian.PutUint16(tmp, s.KEM)
	buf = append(buf, tmp...)
	binary.BigEndian.PutUint16(tmp, s.KDF)
	buf = append(buf, tmp...)
	binary.BigEndian.PutUint16(tmp, s.AEAD)
	buf = append(buf, tmp...)
	return buf
}

// GenerateKeyPair returns a freshly generated HPKE key pair for suite s.
func GenerateKeyPair(rand io.Reader, s Suite) (public, private []byte, err error) {
	suite, err := newCipherSuite(s)
	if err != nil {
		return nil, nil, err
	}
	sk, pk, err := suite.generateKeyPair(rand)
	if err != nil {
		return nil, nil, err
	}
	return pk, sk, nil
}

func (cs *cipherSuite) generateKeyPair(rand io.Reader) ([]byte, []byte, error) {
	priv, err := cs.kem.curve.GenerateKey(rand)
	if err != nil {
		return nil, nil, err
	}
	pk := priv.PublicKey().Bytes()
	sk := priv.Bytes()
	return sk, pk, nil
}

func (cs *cipherSuite) labeledExtract(salt []byte, label string, ikm []byte) []byte {
	labeled := make([]byte, 0, len(hpkeLabel)+len(cs.suiteID)+len(label)+len(ikm))
	labeled = append(labeled, hpkeLabel...)
	labeled = append(labeled, cs.suiteID...)
	labeled = append(labeled, label...)
	labeled = append(labeled, ikm...)
	return kdf.HKDFExtractWith(cs.hash, salt, labeled)
}

func (cs *cipherSuite) labeledExpand(prk []byte, label string, info []byte, length int) ([]byte, error) {
	tmp := make([]byte, 2)
	binary.BigEndian.PutUint16(tmp, uint16(length))
	labeled := make([]byte, 0, len(tmp)+len(hpkeLabel)+len(cs.suiteID)+len(label)+len(info))
	labeled = append(labeled, tmp...)
	labeled = append(labeled, hpkeLabel...)
	labeled = append(labeled, cs.suiteID...)
	labeled = append(labeled, label...)
	labeled = append(labeled, info...)
	return kdf.HKDFExpandWith(cs.hash, prk, labeled, length)
}

func (cs *cipherSuite) extractAndExpand(dh, kemContext []byte) ([]byte, error) {
	eaePRK := cs.labeledExtract(nil, "eae_prk", dh)
	return cs.labeledExpand(eaePRK, "shared_secret", kemContext, cs.hashLen)
}

func (cs *cipherSuite) keySchedule(mode byte, sharedSecret, info []byte) (*hpkeContext, error) {
	var psk []byte
	var pskID []byte
	pskIDHash := cs.labeledExtract(nil, "psk_id_hash", pskID)
	infoHash := cs.labeledExtract(nil, "info_hash", info)
	s := cs.labeledExtract(sharedSecret, "s", psk)
	context := encodeContext(mode, pskIDHash, infoHash)
	keyMaterial, err := cs.labeledExpand(s, "key", context, cs.keySize)
	if err != nil {
		return nil, err
	}
	baseNonce, err := cs.labeledExpand(s, "base_nonce", context, cs.nonceSize)
	if err != nil {
		return nil, err
	}
	exporterSecret, err := cs.labeledExpand(s, "exp", context, cs.hashLen)
	if err != nil {
		return nil, err
	}
	return newContext(cs, keyMaterial, baseNonce, exporterSecret), nil
}

func (cs *cipherSuite) encapsulate(rand io.Reader, pkR []byte) ([]byte, []byte, error) {
	peer, err := cs.kem.curve.NewPublicKey(pkR)
	if err != nil {
		return nil, nil, err
	}
	skE, err := cs.kem.curve.GenerateKey(rand)
	if err != nil {
		return nil, nil, err
	}
	enc := skE.PublicKey().Bytes()
	shared, err := skE.ECDH(peer)
	if err != nil {
		return nil, nil, err
	}
	kemContext := make([]byte, 0, len(enc)+len(pkR))
	kemContext = append(kemContext, enc...)
	kemContext = append(kemContext, pkR...)
	sharedSecret, err := cs.extractAndExpand(shared, kemContext)
	if err != nil {
		return nil, nil, err
	}
	return enc, sharedSecret, nil
}

func (cs *cipherSuite) decapsulate(enc, skR []byte) ([]byte, error) {
	priv, err := cs.kem.curve.NewPrivateKey(skR)
	if err != nil {
		return nil, err
	}
	peer, err := cs.kem.curve.NewPublicKey(enc)
	if err != nil {
		return nil, err
	}
	shared, err := priv.ECDH(peer)
	if err != nil {
		return nil, err
	}
	pkR := priv.PublicKey().Bytes()
	kemContext := make([]byte, 0, len(enc)+len(pkR))
	kemContext = append(kemContext, enc...)
	kemContext = append(kemContext, pkR...)
	sharedSecret, err := cs.extractAndExpand(shared, kemContext)
	if err != nil {
		return nil, err
	}
	return sharedSecret, nil
}

func encodeContext(mode byte, pskIDHash, infoHash []byte) []byte {
	out := make([]byte, 1+len(pskIDHash)+len(infoHash))
	out[0] = mode
	copy(out[1:], pskIDHash)
	copy(out[1+len(pskIDHash):], infoHash)
	return out
}

const hpkeLabel = "HPKE-v1"

type dhkem struct {
	curve ecdh.Curve
}

func newDHKEMX25519() *dhkem {
	return &dhkem{curve: ecdh.X25519()}
}

type aeadScheme interface {
	Seal(key, nonce, aad, pt []byte) ([]byte, error)
	Open(key, nonce, aad, ct []byte) ([]byte, error)
}

type aeadImpl struct {
	cipher    aead.Aead
	keySize   int
	nonceSize int
}

func newAESGCM128Scheme() aeadScheme {
	return &aeadImpl{cipher: aead.NewAESGCM(), keySize: 16, nonceSize: 12}
}

func newChaCha20Poly1305Scheme() aeadScheme {
	return &aeadImpl{cipher: aead.NewChaCha20Poly1305(), keySize: 32, nonceSize: 12}
}

func (a *aeadImpl) Seal(key, nonce, aad, pt []byte) ([]byte, error) {
	return a.cipher.Encrypt(key, nonce, aad, pt)
}

func (a *aeadImpl) Open(key, nonce, aad, ct []byte) ([]byte, error) {
	return a.cipher.Decrypt(key, nonce, aad, ct)
}

func (a *aeadImpl) keyLen() int   { return a.keySize }
func (a *aeadImpl) nonceLen() int { return a.nonceSize }

type hpkeContext struct {
	suite          *cipherSuite
	key            *secret.SymmetricKey
	baseNonce      []byte
	seq            []byte
	exhausted      bool
	exporterSecret []byte
	aead           aeadScheme
}

func newContext(suite *cipherSuite, keyMaterial, baseNonce, exporterSecret []byte) *hpkeContext {
	ctx := &hpkeContext{
		suite:          suite,
		key:            secret.SymmetricKeyFrom(keyMaterial),
		baseNonce:      secret.CloneBytes(baseNonce),
		seq:            make([]byte, len(baseNonce)),
		exporterSecret: secret.CloneBytes(exporterSecret),
		aead:           suite.aead,
	}
	return ctx
}

func (c *hpkeContext) destroy() {
	if c == nil {
		return
	}
	if c.key != nil {
		c.key.Destroy()
	}
	secret.WipeBytes(c.baseNonce)
	secret.WipeBytes(c.seq)
	secret.WipeBytes(c.exporterSecret)
	c.exhausted = true
}

func (c *hpkeContext) nextNonce() ([]byte, error) {
	if c.exhausted {
		return nil, errors.New("hpke: nonce exhausted")
	}
	nonce := make([]byte, len(c.baseNonce))
	copy(nonce, c.baseNonce)
	for i := range nonce {
		nonce[i] ^= c.seq[i]
	}
	if !incrementBE(c.seq) {
		c.exhausted = true
	}
	return nonce, nil
}

func (c *hpkeContext) export(info []byte, length int) ([]byte, error) {
	if c.exhausted && length == 0 {
		return nil, nil
	}
	return c.suite.labeledExpand(c.exporterSecret, "sec", info, length)
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
