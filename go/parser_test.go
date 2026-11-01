package libv

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const minimal = `' minimal
v device nokia-c22-03
`

const full = `' vyzorix.v
v device nokia-c22-03
vv org vyzorix-workshop
vv name Bench 3
vv cloud
vvv ws wss://api.vyzorix.com/ws/device
vvv hb 30s
vvv backoff 1s>30s
vv apps root /data/local/vyzorix-apps > /home/apps autostart true
vvv app flasher-server 3000
vvvv cmd npm start -- --port 3000
`

func TestParseMinimal(t *testing.T) {
	doc, err := Parse(minimal)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if doc.Signed {
		t.Fatal("a document with no sig line is unsigned")
	}
	if len(doc.Root.Children) != 1 {
		t.Fatalf("expected 1 root child, got %d", len(doc.Root.Children))
	}
	if got := doc.Root.Children[0].Tokens; got[0] != "device" || got[1] != "nokia-c22-03" {
		t.Fatalf("unexpected tokens: %v", got)
	}
}

func TestParseBuildsTree(t *testing.T) {
	doc, err := Parse(full)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	device := doc.Root.Children[0]
	if device.Key() != "device" {
		t.Fatalf("root child = %q", device.Key())
	}

	// vv name Bench 3 -> one node with three tokens, because the sketch's own
	// example has an unquoted multi-word value.
	names := device.Find("name")
	if len(names) != 1 || len(names[0].Tokens) != 3 {
		t.Fatalf("name node = %+v", names)
	}

	// `vv apps root ...` is depth 2 under device, and `vvv app flasher-server
	// 3000` is depth 3, so its parent is the nearest preceding depth-2 node —
	// `apps`. Find walks by key from the given node, so the path is "apps.app".
	app := device.Find("apps.app")
	if len(app) != 1 {
		t.Fatalf("apps.app not found: %+v", app)
	}
	if len(app[0].Tokens) < 3 || app[0].Tokens[1] != "flasher-server" {
		t.Fatalf("app tokens = %v", app[0].Tokens)
	}
	if len(app[0].Children) != 1 || app[0].Children[0].Tokens[0] != "cmd" {
		t.Fatalf("app children = %+v", app[0].Children)
	}
}

// TestIndentedDocumentParsesIdentically is SPEC §7 deviation 1: the reference
// counted depth from the raw line, so an indented document silently reparented.
func TestIndentedDocumentParsesIdentically(t *testing.T) {
	indented := ""
	for _, ln := range strings.Split(strings.TrimRight(full, "\n"), "\n") {
		indented += "    " + ln + "\n"
	}

	flush, err := Parse(full)
	if err != nil {
		t.Fatalf("flush: %v", err)
	}
	spaced, err := Parse(indented)
	if err != nil {
		t.Fatalf("indented: %v", err)
	}

	if len(flush.Root.Children) != len(spaced.Root.Children) {
		t.Fatalf("indented parse differs: %d vs %d root children",
			len(flush.Root.Children), len(spaced.Root.Children))
	}
	if len(flush.Root.Children[0].Children) != len(spaced.Root.Children[0].Children) {
		t.Fatal("indented parse attached nodes to a different parent")
	}
}

func TestDepthJumpIsAnError(t *testing.T) {
	_, err := Parse("v a\nvvv c\n")
	if err == nil {
		t.Fatal("a depth jump must be an error")
	}
	if !errors.Is(err, ErrDepthJump) {
		t.Fatalf("expected ErrDepthJump, got %v", err)
	}
}

func TestUnclosedQuoteIsAnError(t *testing.T) {
	_, err := Parse("v name \"Bench 3\n")
	if err == nil || !errors.Is(err, ErrUnclosedQuote) {
		t.Fatalf("expected ErrUnclosedQuote, got %v", err)
	}
}

func TestQuotedTokenIsOneToken(t *testing.T) {
	doc, err := Parse("v name \"Bench 3\"\n")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	tokens := doc.Root.Children[0].Tokens
	if len(tokens) != 2 || tokens[1] != "Bench 3" {
		t.Fatalf("quoted token decoded to %v", tokens)
	}
}

func TestSignatureMustBeLast(t *testing.T) {
	text := "v sig ecdsa-p256 AAAA\nv device x\n"
	if _, err := Parse(text); err == nil || !errors.Is(err, ErrSignatureNotLast) {
		t.Fatalf("expected ErrSignatureNotLast, got %v", err)
	}
}

func TestSignatureMustBeDepthOne(t *testing.T) {
	if _, err := Parse("vv sig ecdsa-p256 AAAA\n"); err == nil {
		t.Fatal("a signature below depth 1 must be refused")
	}
}

// TestCanonicalExcludesCommentsAndSignature proves whitespace, comments and the
// signature line do not affect what is signed.
func TestCanonicalExcludesCommentsAndSignature(t *testing.T) {
	a, err := CanonicalString("v device x\n")
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	b, err := CanonicalString("' comment\n\n  v device x\nv sig ecdsa-p256 AAAA\n")
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	if string(a) != string(b) {
		t.Fatalf("canonical forms differ:\n%q\n%q", a, b)
	}
}

func TestSignAndVerifyRoundTrip(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	signer, err := NewSignerFromPEM(string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})))
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	signed, err := signer.Sign(full)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	doc, err := Parse(signed)
	if err != nil {
		t.Fatalf("parse signed: %v", err)
	}
	if !doc.Signed || doc.Signature.Algorithm != AlgECDSAP256 {
		t.Fatalf("signature not recognised: %+v", doc.Signature)
	}
	if err := Verify(doc, signed, &key.PublicKey, nil); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestTamperedDocumentFailsVerification(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	signer, _ := NewSignerFromPEM(string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})))

	signed, err := signer.Sign(full)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	tampered := strings.Replace(signed, "vv org vyzorix-workshop", "vv org attacker-org", 1)
	doc, err := Parse(tampered)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Verify(doc, tampered, &key.PublicKey, nil); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("a tampered document must fail: %v", err)
	}
}

func TestWrongKeyFailsVerification(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	signer, _ := NewSignerFromPEM(string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})))
	signed, _ := signer.Sign(full)

	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	doc, _ := Parse(signed)
	if err := Verify(doc, signed, &other.PublicKey, nil); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("a signature must not verify under the wrong key: %v", err)
	}
}

func TestUnsignedDocumentReportsNoSignature(t *testing.T) {
	doc, _ := Parse(full)
	if err := Verify(doc, full, nil, nil); !errors.Is(err, ErrNoSignature) {
		t.Fatalf("expected ErrNoSignature, got %v", err)
	}
}

// TestHMACLegacyStillVerifies proves the retired algorithm still checks, so an
// older document does not silently become untrusted.
func TestHMACLegacyStillVerifies(t *testing.T) {
	secret := []byte("legacy-secret")
	body := "v device x\n"
	canonical, _ := CanonicalString(body)

	mac := hmacSHA256(secret, canonical)
	signed := body + "v sig hmac-sha256 " + mac + "\n"

	doc, err := Parse(signed)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := Verify(doc, signed, nil, secret); err != nil {
		t.Fatalf("legacy HMAC must verify: %v", err)
	}
	if err := Verify(doc, signed, nil, []byte("wrong")); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("a wrong HMAC key must fail: %v", err)
	}
}

func TestAlgorithmMismatchIsRefusedNotSkipped(t *testing.T) {
	// An ECDSA document verified with only an HMAC key must not fall through to
	// "ok" — that would be a silent pass.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	signer, _ := NewSignerFromPEM(string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})))
	signed, _ := signer.Sign(full)

	doc, _ := Parse(signed)
	if err := Verify(doc, signed, nil, []byte("some-hmac-key")); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("expected ErrUnsupportedAlgorithm, got %v", err)
	}
}

// TestVectors runs every file in vectors/. This is the cross-language contract:
// the Kotlin implementation must produce the same results on the same files.
func TestVectors(t *testing.T) {
	dir := filepath.Join("..", "vectors")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Skipf("no vectors directory: %v", err)
	}

	keyPEM, err := os.ReadFile(filepath.Join(dir, "keys", "vector_pub.pem"))
	if err != nil {
		t.Skipf("no vector public key: %v", err)
	}
	pub, err := DecodePublicKey(string(keyPEM))
	if err != nil {
		t.Fatalf("vector key: %v", err)
	}

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".v") {
			continue
		}
		name := e.Name()
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			text := string(data)

			doc, parseErr := Parse(text)
			expectParseError := strings.Contains(name, "depth_jump")
			if expectParseError {
				if parseErr == nil {
					t.Fatal("expected a parse error")
				}

				return
			}
			if parseErr != nil {
				t.Fatalf("parse: %v", parseErr)
			}

			expectBadSig := strings.Contains(name, "tampered")
			if !doc.Signed {
				return
			}

			// The legacy HMAC vector carries its own secret; every other vector is
			// ECDSA and verifies against the vector public key.
			var hmacKey []byte
			if doc.Signature.Algorithm == AlgHMACSHA256 {
				secretFile := filepath.Join(dir, strings.TrimSuffix(name, ".v")+".secret")
				hmacKey, err = os.ReadFile(secretFile)
				if err != nil {
					t.Fatalf("legacy vector needs its secret: %v", err)
				}
			}

			err = Verify(doc, text, pub, hmacKey)
			switch {
			case expectBadSig && !errors.Is(err, ErrBadSignature):
				t.Fatalf("expected a bad signature, got %v", err)
			case !expectBadSig && err != nil:
				t.Fatalf("verify: %v", err)
			}
		})
	}
}

// hmacSHA256 is a test-local helper so the legacy path can be exercised.
func hmacSHA256(key, msg []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)

	return hex.EncodeToString(mac.Sum(nil))
}
