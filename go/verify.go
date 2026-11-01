package libv

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// Algorithm names carried on the signature line. The format does not privilege
// one, but ecdsa-p256 is the default because it needs no shared secret and so
// nothing has to be transmitted to the device.
const (
	AlgECDSAP256  = "ecdsa-p256"
	AlgHMACSHA256 = "hmac-sha256"
)

var (
	// ErrNoSignature is returned by Verify on an unsigned document.
	ErrNoSignature = errors.New("document is not signed")
	// ErrBadSignature is returned when the signature does not match.
	ErrBadSignature = errors.New("signature does not match")
	// ErrBadKey is returned when a key cannot be parsed.
	ErrBadKey = errors.New("malformed key")
)

// EncodePublicKey serialises a P-256 public key as PEM. PEM rather than raw bytes
// so the value is self-describing and a corrupt one fails to parse rather than
// being misread.
func EncodePublicKey(pub *ecdsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

// DecodePublicKey parses a PEM public key and requires P-256.
func DecodePublicKey(encoded string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(encoded))
	if block == nil {
		return nil, ErrBadKey
	}

	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadKey, err)
	}

	pub, ok := parsed.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, ErrBadKey
	}

	return pub, nil
}

// Signer signs a document. The private key stays with the signer; the verifier
// needs only the public half, which is what removes the shared secret.
type Signer struct {
	key *ecdsa.PrivateKey
}

// NewSignerFromPEM builds a signer from a PKCS#8 PEM private key.
func NewSignerFromPEM(privateKeyPEM string) (*Signer, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, ErrBadKey
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadKey, err)
	}

	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, ErrBadKey
	}

	return &Signer{key: key}, nil
}

// PublicKeyPEM returns the public half, for pinning in a verifier.
func (s *Signer) PublicKeyPEM() (string, error) {
	return EncodePublicKey(&s.key.PublicKey)
}

// Sign appends a signature line to a document body and returns the complete
// document. The body must not already contain a signature line.
func (s *Signer) Sign(body string) (string, error) {
	canonical, err := CanonicalString(body)
	if err != nil {
		return "", err
	}

	digest := sha256.Sum256(canonical)
	sig, err := ecdsa.SignASN1(rand.Reader, s.key, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}

	line := fmt.Sprintf("v sig %s %s", AlgECDSAP256, base64.StdEncoding.EncodeToString(sig))
	if !strings.HasSuffix(body, "\n") {
		body += "\n"
	}

	return body + line + "\n", nil
}

// Verify checks a document's signature. It returns ErrNoSignature for an
// unsigned document so the caller decides whether that is acceptable.
//
// ecdsaKey is required for an ecdsa-p256 document; hmacKey for a legacy
// hmac-sha256 one. Passing the wrong kind for the document's algorithm is
// ErrUnsupportedAlgorithm, never a silent pass.
func Verify(doc *Document, text string, ecdsaKey *ecdsa.PublicKey, hmacKey []byte) error {
	if doc.Signature == nil {
		return ErrNoSignature
	}

	canonical, err := CanonicalString(text)
	if err != nil {
		return err
	}

	switch doc.Signature.Algorithm {
	case AlgECDSAP256:
		if ecdsaKey == nil {
			return ErrUnsupportedAlgorithm
		}
		sig, err := base64.StdEncoding.DecodeString(doc.Signature.Value)
		if err != nil {
			return ErrBadSignature
		}
		digest := sha256.Sum256(canonical)
		if !ecdsa.VerifyASN1(ecdsaKey, digest[:], sig) {
			return ErrBadSignature
		}

		return nil

	case AlgHMACSHA256:
		if len(hmacKey) == 0 {
			return ErrUnsupportedAlgorithm
		}
		mac := hmac.New(sha256.New, hmacKey)
		mac.Write(canonical)
		expected := hex.EncodeToString(mac.Sum(nil))
		if subtle.ConstantTimeCompare([]byte(expected), []byte(doc.Signature.Value)) != 1 {
			return ErrBadSignature
		}

		return nil

	default:
		return fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, doc.Signature.Algorithm)
	}
}

// HMACHex computes the legacy HMAC-SHA256 of msg as lowercase hex. Exported so
// the vector generator and any reimplementation compute it identically.
func HMACHex(key, msg []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)

	return hex.EncodeToString(mac.Sum(nil))
}
