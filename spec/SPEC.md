# libv — specification v1

A line-oriented, position-based configuration format. Two properties make it
unusual, and both are deliberate:

- **Depth is the count of leading `v` characters**, not indentation. No language
  uses a repeating letter for depth, so the marker cannot be confused with content.
- **Tokens are positional, not key:value.** `vvv app flasher-server 3000` means
  type `app`, name `flasher-server`, port `3000`. Order carries meaning, as in an
  assembly line.

One character, `>`, is the only operator, and its meaning comes from context: a
bind/alias, or a range.

---

## 1. Lexical structure

A document is a sequence of lines. Each line is one of:

| Line | Meaning |
|:--|:--|
| blank | ignored |
| starts with `'` (after trimming) | comment; the whole line is ignored |
| starts with `v` (after trimming) | a node |
| anything else | ignored, not an error |

**Leading whitespace is insignificant.** `  vvv app x` and `vvv app x` are the
same node. This is a deliberate deviation from a naive "count the `v` at column
zero" reading: a document indented for readability must parse identically to the
same document flush-left. (The reference sketch counted from the raw line, which
made an indented line depth 0 — see §7.)

**Depth is `count(leading 'v' after trimming)`.** Depth must be ≥ 1 for a node.

**Tokens** follow the `v` run and are separated by runs of spaces. A token is:

- an unquoted run of non-space characters, or
- a `"double quoted"` string, which may contain spaces.

There is no escape sequence inside a quoted token. A `"` cannot appear in a
quoted token; this is a deliberate simplification, and it is why the format is
for machine-written config rather than hand-authored prose.

A quoted token's value is the text **between** the quotes. Quotes are not part of
the value. `"Bench 3"` and `Bench` `3` are different: the first is one token, the
second two.

## 2. Structure

Depth defines a tree. A node at depth `d` is a child of the nearest preceding node
at depth `d-1`. The implicit root is depth 0.

A depth may **increase by at most one** from the previous node's depth. A jump
(depth 1 → depth 3) is an error: it has no parent to attach to, so accepting it
would silently reparent the node to the last depth-2 node, or to the root.

A depth may decrease by any amount.

```
v device nokia-c22-03          depth 1, child of root
vv org vyzorix                 depth 2, child of device
vvv ws wss://...               depth 3, child of org
vv name Bench 3                depth 2, child of device
```

Errors:

| Condition | Result |
|:--|:--|
| depth increases by more than 1 | parse error |
| depth is 0 on a `v` line | parse error (a node must have depth ≥ 1) |
| unclosed `"` | parse error |
| a signature line that is not the last node | parse error |

## 3. The `>` operator

`A > B` means: take the token immediately before `>`, the `>`, and the token
immediately after, and interpret them together. `>` may not be the first or last
token of a line.

Two meanings, by the shape of its operands:

| Form | Meaning |
|:--|:--|
| `path > path` | bind / alias: the left is the source, the right the destination |
| `duration > duration` | a range: minimum to maximum |

The form is decided by whether both operands parse as durations. A duration is
`<number><unit>` with unit `ms`, `s`, `m` or `h`, and both operands must carry a
unit for the range reading.

## 4. Signature

The **last node in the document** may be a signature line:

```
v sig ecdsa-p256 <base64>
```

It must be at depth 1. Its presence is what makes a document signed; a document
without it is unsigned, which is a valid state (a device may hold an unsigned
draft) but must be treated as untrusted.

**Algorithm is named in the line**, so the format does not privilege one:

| Token 2 | Meaning | Token 3 |
|:--|:--|:--|
| `ecdsa-p256` | ECDSA over P-256, SHA-256 digest, ASN.1 DER signature | base64 |
| `hmac-sha256` | HMAC-SHA256 (legacy) | lowercase hex |

`ecdsa-p256` is the default and the reason this format carries a signature at all:
the signer holds a private key that never leaves it, and the verifier holds only a
public key. **No shared secret is required, so none has to be transmitted.**
`hmac-sha256` is retained so an older document still parses; a verifier that
supports only one algorithm must reject the other rather than fall through.

## 5. The canonical string

The signature covers a canonical form, not the raw bytes, so that whitespace,
indentation, comments and line endings do not affect it. The canonical form is:

```
for each node line, in order, excluding the signature line and comments:
    ("v" * depth) + " " + tokens.join(" ") + "\n"
```

where `tokens` are the **decoded** token values (quotes removed), joined by a
single space. Blank lines, comment lines and the signature line itself are
excluded. The result is UTF-8, with `\n` line endings regardless of platform.

Two properties are load-bearing:

1. **One implementation.** The canonical string is produced by a single function
   used by both `sign` and `verify`. Two independent implementations of the same
   canonicalisation are two things that can disagree, and the signature depends on
   them agreeing forever.
2. **Unambiguous.** Because tokens are joined with a single space and a token can
   never contain a space unless quoted, and because depth is written explicitly,
   two different documents cannot produce the same canonical string.

> **Signed by depth** — the sketch's phrase for "the last line is always depth 1,
> so it signs everything above it". That is exactly what §5 achieves: the canonical
> string is every node above the signature line, in order. The depth of the
> signature line is a formatting requirement, not the mechanism; the mechanism is
> that the canonical form excludes the signature.

## 6. Verification

To verify:

1. Parse. Any parse error is a verification failure.
2. If there is no signature line, the document is unsigned.
3. Recompute the canonical string over the lines above the signature.
4. Verify the signature with the algorithm named on the line.

A verifier **must** also reject a document whose signature line is not last. The
sketch's `buildCanonical` skipped any line starting with `v hmac`, which would let
a second signature line appear mid-document and be excluded from the MAC.

## 7. Deviations from the reference sketch

Recorded because they are behaviour changes, not refactors.

| # | Sketch | Spec | Why |
|:--|:--|:--|:--|
| 1 | `raw.takeWhile { it == 'v' }` | count on the **trimmed** line | An indented line got depth 0 and was silently reparented to the root; the next line then threw. The example document is itself indented. |
| 2 | `parse()` builds a canonical string and discards it; `verify()` calls a separate `buildCanonical()` | one canonicaliser | Two implementations of a security-critical string will drift. |
| 3 | `buildCanonical` skips any line starting `v hmac` | only the **last** node may be a signature | Otherwise a second signature line mid-document is excluded from the MAC. |
| 4 | no depth-0 check | depth 0 is an error | A node with no `v` is not a node. |
| 5 | HMAC only | algorithm named per line, ECDSA default | Retires the shared secret, which otherwise has to be delivered to every device. |

## 8. Grammar (EBNF)

```ebnf
document   = { line } ;
line       = blank | comment | node ;
blank      = ws , newline ;
comment    = ws , "'" , { any } , newline ;
node       = ws , vrun , ws , token , { ws , token } , newline ;
vrun       = "v" , { "v" } ;                    (* depth = length *)
token      = bare | quoted ;
bare       = { any - ( space | newline ) } ;
quoted     = '"' , { any - '"' } , '"' ;
ws         = { " " | "\t" } ;
duration   = number , unit ;
unit       = "ms" | "s" | "m" | "h" ;
```

## 9. Conformance

`vectors/` holds the contract. Both implementations must pass every vector:

| Vector | Expectation |
|:--|:--|
| `01_minimal.v` | parses; 1 node; unsigned |
| `02_full.v` | parses; full tree; signature verifies against the vector key |
| `03_tampered.v` | parses; signature **fails** |
| `04_indented.v` | parses identically to `02_full.v` — the §7 deviation |
| `05_depth_jump.v` | parse **error** |
| `06_hmac_legacy.v` | parses; legacy HMAC verifies |

A change to a vector is a change to the format and requires both implementations
to change together. That is the point of the folder.
