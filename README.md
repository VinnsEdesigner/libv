# libv

Parser and verifier for the `vyzorix.v` configuration format.

The format is line-oriented. **Depth is the count of leading `v` characters**, and
**tokens are positional** rather than `key: value`:

```
v device nokia-c22-03
vv org vyzorix-workshop-kisumu
vv cloud
vvv ws wss://api.vyzorix.com/ws/device
vvv hb 30s
vvv backoff 1s>30s
vv apps root /data/local/vyzorix-apps > /home/apps autostart true
vvv app flasher-server 3000
vvvv cmd npm start -- --port 3000
v sig ecdsa-p256 MEYCIQ...
```

`>` is the only operator: `A > B` is a bind/alias, and `A > B` where both sides are
durations is a range.

The last line is a signature over everything above it, so a file is signed by
construction rather than by convention. **ECDSA P-256 by default**, which means the
signer holds a private key that never leaves it and the verifier holds only a public
key — no shared secret, so none has to be transmitted.

Full grammar: [`spec/SPEC.md`](spec/SPEC.md).

---

## Layout

```
spec/       the frozen grammar, v1
vectors/    the cross-language conformance contract
go/         Go implementation   (module github.com/VinnsEdesigner/libv/go)
kotlin/     Kotlin/JVM implementation
```

## Using it

**Go:**

```bash
go get github.com/VinnsEdesigner/libv/go
```

```go
doc, err := libv.Parse(text)
if err != nil { /* malformed */ }
if doc.Signed {
    err = libv.Verify(doc, text, publicKey, nil)
}
```

**Kotlin/JVM:**

```kotlin
val doc = VParser.parse(text)
if (doc.signed) {
    VVerifier.verify(doc, text, ecdsaKey = publicKey)
}
```

## The vectors are the contract

`vectors/` holds files both implementations must agree on. This matters more than
usual here: the canonical string that gets signed is produced by each
implementation, so if the two ever disagree by a single byte, signatures stop
verifying. The vectors are how that is caught rather than discovered.

| Vector | Expectation |
|:--|:--|
| `01_minimal.v` | parses; one node; unsigned |
| `02_full.v` | parses; signature verifies |
| `02_full.canonical` | the exact bytes the signature covers |
| `03_tampered.v` | parses; signature **fails** |
| `04_indented.v` | parses identically to `02_full.v` |
| `05_depth_jump.v` | parse **error** |
| `06_hmac_legacy.v` | legacy HMAC still verifies |

`vectors/keys/vector_priv.pem` is committed on purpose: it signs the vectors and
protects nothing. **Never reuse it.**

Regenerate after a deliberate format change:

```bash
cd go && go run ./cmd/genvectors ../vectors
```

A change to a vector is a change to the format, and both implementations must
change together.

## Running the tests

```bash
cd go     && go test ./...
cd kotlin && ./gradlew test
```

## Deviations from the original sketch

Recorded in `spec/SPEC.md` §7, with reasons. The two that are behaviour, not
refactors:

1. **Depth counts on the trimmed line.** The sketch counted from the raw line, so an
   indented document got depth 0 for every node and silently reparented them to the
   root — then threw on the next line. `04_indented.v` makes this testable.
2. **One canonicaliser.** The sketch built the canonical string in `parse()` and
   discarded it, then rebuilt it in `verify()` with different logic. Two
   implementations of a security-critical string will drift.
