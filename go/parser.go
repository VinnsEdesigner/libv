// Package libv parses and verifies the vyzorix.v configuration format.
//
// The format is line-oriented: depth is the count of leading 'v' characters and
// tokens are positional. See spec/SPEC.md for the frozen grammar; this file is an
// implementation of it, and vectors/ is the conformance contract.
package libv

import (
	"errors"
	"fmt"
	"strings"
)

// Node is one parsed line: its depth, its decoded tokens, and its children.
type Node struct {
	Depth    int
	Tokens   []string
	Children []*Node
}

// Key returns the first token, which is the node's type/name by convention.
// Empty for a node with no tokens, which the parser never produces.
func (n *Node) Key() string {
	if len(n.Tokens) == 0 {
		return ""
	}

	return n.Tokens[0]
}

// Find returns every descendant whose first token equals path, walking one
// segment per dot. Find("app.flasher-server") returns the node with tokens
// ["flasher-server", ...] under the node with tokens ["app", ...].
func (n *Node) Find(path string) []*Node {
	current := []*Node{n}
	for _, segment := range strings.Split(path, ".") {
		var next []*Node
		for _, parent := range current {
			for _, child := range parent.Children {
				if child.Key() == segment {
					next = append(next, child)
				}
			}
		}
		current = next
		if len(current) == 0 {
			return nil
		}
	}

	return current
}

// ParseError describes a malformed document, with the 1-based line number.
//
// Err is the sentinel a caller can test with errors.Is; Msg carries the detail.
// Without Unwrap, errors.Is would never match and every caller would have to
// string-match the message.
type ParseError struct {
	Err  error
	Line int
	Msg  string
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("libv: line %d: %s", e.Line, e.Msg)
}

// Unwrap exposes the sentinel so errors.Is(err, ErrDepthJump) works.
func (e *ParseError) Unwrap() error { return e.Err }

// Document is a parsed file: the tree, and the signature line if present.
type Document struct {
	Root      *Node
	Signature *Signature
	// Signed reports whether a signature line was present.
	Signed bool
}

// Signature is the parsed signature line.
type Signature struct {
	Algorithm string // "ecdsa-p256" or "hmac-sha256"
	Value     string // base64 (ECDSA) or lowercase hex (HMAC)
	Depth     int
	Line      int
}

// Errors a caller may need to distinguish.
var (
	// ErrDepthJump is returned when a node's depth is more than one deeper than
	// the previous node's. Such a node has no parent, so accepting it would
	// silently reparent it.
	ErrDepthJump = errors.New("depth jump")
	// ErrDepthZero is returned for a node line with no leading 'v'.
	ErrDepthZero = errors.New("depth must be at least 1")
	// ErrUnclosedQuote is returned for a token with an opening quote and no close.
	ErrUnclosedQuote = errors.New("unclosed quote")
	// ErrSignatureNotLast is returned when a signature line is followed by a node.
	ErrSignatureNotLast = errors.New("signature line must be the last node")
	// ErrUnsupportedAlgorithm is returned by Verify for an algorithm it cannot check.
	ErrUnsupportedAlgorithm = errors.New("unsupported signature algorithm")
)

// Parse reads a document. It is strict about the two structural errors that
// would otherwise silently produce a wrong tree (a depth jump, and a depth-0
// node) and lenient about everything else, matching SPEC.md §1.
func Parse(text string) (*Document, error) {
	root := &Node{Depth: 0}
	stack := []*Node{root}
	prevDepth := 0

	var sig *Signature
	lines := strings.Split(text, "\n")

	for i, raw := range lines {
		lineNo := i + 1
		trimmed := strings.TrimSpace(raw)

		if trimmed == "" || strings.HasPrefix(trimmed, "'") {
			continue
		}
		if !strings.HasPrefix(trimmed, "v") {
			// SPEC §1: a line that is not blank, a comment or a node is ignored.
			continue
		}

		depth := 0
		for depth < len(trimmed) && trimmed[depth] == 'v' {
			depth++
		}

		// A 'v' run must be followed by a separator or the line ends. "value" is
		// not a node of depth 1; it is a word that happens to start with 'v'.
		if depth < len(trimmed) && trimmed[depth] != ' ' && trimmed[depth] != '\t' {
			continue
		}

		if depth == 0 {
			return nil, &ParseError{Err: ErrDepthZero, Line: lineNo, Msg: ErrDepthZero.Error()}
		}
		if depth > prevDepth+1 {
			return nil, &ParseError{
				Err:  ErrDepthJump,
				Line: lineNo,
				Msg:  fmt.Sprintf("%v: %d -> %d", ErrDepthJump, prevDepth, depth),
			}
		}

		content := strings.TrimSpace(trimmed[depth:])
		if content == "" {
			// A bare 'v' line carries no tokens; SPEC §1 requires at least one.
			return nil, &ParseError{Line: lineNo, Msg: "node has no tokens"}
		}

		tokens, err := tokenize(content)
		if err != nil {
			return nil, &ParseError{Err: err, Line: lineNo, Msg: err.Error()}
		}

		// The signature is recognised by its first two tokens, not by a substring,
		// so a node whose value merely mentions "sig" is unaffected.
		if len(tokens) >= 3 && tokens[0] == "sig" {
			if sig != nil {
				return nil, &ParseError{Line: lineNo, Msg: "duplicate signature line"}
			}
			if depth != 1 {
				return nil, &ParseError{Line: lineNo, Msg: "signature must be at depth 1"}
			}
			sig = &Signature{Algorithm: tokens[1], Value: tokens[2], Depth: depth, Line: lineNo}
			prevDepth = depth
			continue
		}

		if sig != nil {
			// A node after the signature would be excluded from the canonical
			// string, so it would be unauthenticated while appearing signed.
			return nil, &ParseError{Err: ErrSignatureNotLast, Line: lineNo, Msg: ErrSignatureNotLast.Error()}
		}

		for len(stack) > depth {
			stack = stack[:len(stack)-1]
		}

		node := &Node{Depth: depth, Tokens: tokens}
		parent := stack[len(stack)-1]
		parent.Children = append(parent.Children, node)
		stack = append(stack, node)
		prevDepth = depth
	}

	return &Document{Root: root, Signature: sig, Signed: sig != nil}, nil
}

// tokenize splits a node's content into decoded tokens. A quoted token may
// contain spaces; quotes are not part of the value.
func tokenize(s string) ([]string, error) {
	var out []string

	i := 0
	for i < len(s) {
		switch s[i] {
		case ' ', '\t':
			i++
		case '"':
			end := strings.IndexByte(s[i+1:], '"')
			if end == -1 {
				return nil, ErrUnclosedQuote
			}
			out = append(out, s[i+1:i+1+end])
			i += end + 2
		default:
			end := i
			for end < len(s) && s[end] != ' ' && s[end] != '\t' && s[end] != '"' {
				end++
			}
			out = append(out, s[i:end])
			i = end
		}
	}

	return out, nil
}

// CanonicalString returns the bytes a signature covers: every node line above the
// signature, in order, with depth written explicitly and tokens joined by one
// space. It is the single canonicaliser used by both signing and verification —
// two implementations of this string would be two things that can disagree.
func CanonicalString(text string) ([]byte, error) {
	var b strings.Builder

	for _, raw := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "'") {
			continue
		}
		if !strings.HasPrefix(trimmed, "v") {
			continue
		}

		depth := 0
		for depth < len(trimmed) && trimmed[depth] == 'v' {
			depth++
		}
		if depth < len(trimmed) && trimmed[depth] != ' ' && trimmed[depth] != '\t' {
			continue
		}
		if depth == 0 {
			continue
		}

		content := strings.TrimSpace(trimmed[depth:])
		if content == "" {
			continue
		}

		tokens, err := tokenize(content)
		if err != nil {
			return nil, err
		}

		// The signature line is excluded from what it signs.
		if len(tokens) >= 3 && tokens[0] == "sig" {
			continue
		}

		b.WriteString(strings.Repeat("v", depth))
		b.WriteByte(' ')
		b.WriteString(strings.Join(tokens, " "))
		b.WriteByte('\n')
	}

	return []byte(b.String()), nil
}
