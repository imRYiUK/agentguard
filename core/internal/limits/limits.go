// Package limits holds the resource limits AgentGuard applies to every input
// it reads. Every input is untrusted, so each parser checks its input's size
// and nesting depth before it does any work proportional to them.
package limits

import (
	"fmt"
	"io"
	"io/fs"
)

// The limits. They are generous for real inputs and small enough that a
// hostile input cannot exhaust a developer's machine.
const (
	// MaxConfigBytes is the size limit of an Agent Manifest, a Claude Code
	// settings file, and an MCP configuration file.
	MaxConfigBytes = 1 << 20
	// MaxSnapshotBytes is the size limit of a Snapshot file.
	MaxSnapshotBytes = 8 << 20
	// MaxPolicyDocumentBytes is the encoded size limit of one IAM policy
	// document. AWS itself caps a policy at 6,144 characters.
	MaxPolicyDocumentBytes = 256 << 10
	// MaxDepth is the nesting limit of a manifest, a configuration file, and
	// a Snapshot.
	MaxDepth = 32
	// MaxPolicyDepth is the nesting limit of an IAM policy document, counted
	// from the document itself. Real policies nest about six levels.
	MaxPolicyDepth = 16
	// MaxListLength is the limit on the entries of one list in an Agent
	// Manifest.
	MaxListLength = 64
)

// ReadFile reads a file, giving up once it is larger than maxBytes instead
// of reading all of it.
func ReadFile(fsys fs.FS, name string, maxBytes int) ([]byte, error) {
	f, err := fsys.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	content, err := io.ReadAll(io.LimitReader(f, int64(maxBytes)+1))
	if err != nil {
		return nil, err
	}
	if err := CheckSize(len(content), maxBytes); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return content, nil
}

// CheckSize returns an error if n is larger than maxBytes.
func CheckSize(n, maxBytes int) error {
	if n > maxBytes {
		return fmt.Errorf("too large (the limit is %d bytes)", maxBytes)
	}
	return nil
}

// CheckJSON returns an error if content, a JSON document, is larger than
// maxBytes or nests deeper than MaxDepth. It does not need the document to
// be valid JSON, and it allocates nothing, so it is safe to run before
// parsing.
func CheckJSON(content []byte, maxBytes int) error {
	if err := CheckSize(len(content), maxBytes); err != nil {
		return err
	}
	depth, inString, escaped := 0, false, false
	for _, c := range content {
		if inString {
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '{', '[':
			depth++
			if depth > MaxDepth {
				return ErrTooDeep
			}
		case '}', ']':
			if depth > 0 {
				depth--
			}
		}
	}
	return nil
}

// ErrTooDeep is the error for an input that nests deeper than MaxDepth.
var ErrTooDeep = fmt.Errorf("nesting is deeper than the limit of %d levels", MaxDepth)
