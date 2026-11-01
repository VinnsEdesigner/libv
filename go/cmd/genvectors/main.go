// Command genvectors regenerates vectors/ from the format's own canonicaliser.
//
// The vectors are the cross-language contract: the Kotlin implementation must
// agree with these files, so a vector must be produced by the same logic the
// verifier uses rather than by hand. Run from the repo root:
//
//	go run ./go/cmd/genvectors vectors
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	libv "github.com/VinnsEdesigner/libv/go"
)

const fullBody = `v device nokia-c22-03
vv org vyzorix-workshop-kisumu
vv name Bench 3
vv cloud
vvv ws wss://api.vyzorix.com/ws/device
vvv hb 30s
vvv backoff 1s>30s
vv apps root /data/local/vyzorix-apps > /home/apps autostart true
vvv app flasher-server 3000
vvvv cmd npm start -- --port 3000
`

func main() {
	dir := "vectors"
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}

	if err := run(dir); err != nil {
		fmt.Fprintln(os.Stderr, "genvectors:", err)
		os.Exit(1)
	}
}

func run(dir string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	pubPEM, err := libv.EncodePublicKey(&key.PublicKey)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Join(dir, "keys"), 0o755); err != nil {
		return err
	}
	// The private key is committed on purpose: it signs the vectors and protects
	// nothing. It must never be reused for anything else.
	if err := os.WriteFile(filepath.Join(dir, "keys", "vector_priv.pem"), privPEM, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "keys", "vector_pub.pem"), []byte(pubPEM), 0o644); err != nil {
		return err
	}

	signer, err := libv.NewSignerFromPEM(string(privPEM))
	if err != nil {
		return err
	}

	minimal := "v device nokia-c22-03\n"
	if err := os.WriteFile(filepath.Join(dir, "01_minimal.v"), []byte(minimal), 0o644); err != nil {
		return err
	}

	full, err := signer.Sign(fullBody)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "02_full.v"), []byte(full), 0o644); err != nil {
		return err
	}

	// 03: signed, then a field changed. Verification must fail.
	tampered := strings.Replace(full, "vyzorix-workshop-kisumu", "attacker-org", 1)
	if err := os.WriteFile(filepath.Join(dir, "03_tampered.v"), []byte(tampered), 0o644); err != nil {
		return err
	}

	// 04: the same body indented. It must parse identically and verify, which is
	// the SPEC §7 deviation made testable.
	var indented strings.Builder
	for _, ln := range strings.Split(strings.TrimRight(fullBody, "\n"), "\n") {
		indented.WriteString("    ")
		indented.WriteString(ln)
		indented.WriteString("\n")
	}
	indentedSigned, err := signer.Sign(indented.String())
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "04_indented.v"), []byte(indentedSigned), 0o644); err != nil {
		return err
	}

	// 05: a depth jump, which has no parent and must be refused.
	if err := os.WriteFile(filepath.Join(dir, "05_depth_jump.v"), []byte("v a\nvvv c\n"), 0o644); err != nil {
		return err
	}

	// 06: a legacy HMAC document, so the retired algorithm stays tested.
	secret := []byte("vector-legacy-secret")
	body := "v device legacy-device\n"
	canonical, err := libv.CanonicalString(body)
	if err != nil {
		return err
	}
	signed := body + "v sig hmac-sha256 " + libv.HMACHex(secret, canonical) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "06_hmac_legacy.v"), []byte(signed), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "06_hmac_legacy.secret"), secret, 0o644); err != nil {
		return err
	}

	// The canonical form of 02, so a reimplementation can compare byte for byte
	// without writing a verifier first.
	canonFull, err := libv.CanonicalString(full)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "02_full.canonical"), canonFull, 0o644); err != nil {
		return err
	}

	fmt.Println("genvectors: wrote vectors to", dir)

	return nil
}
