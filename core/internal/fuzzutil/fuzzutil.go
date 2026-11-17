// Package fuzzutil holds helpers shared by the parser fuzz tests. It is
// written independently of package limits, so a fuzz test checks the limits
// against a second implementation rather than against themselves.
package fuzzutil

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"go.yaml.in/yaml/v3"
)

// FixtureDir is the CLI's first valid fixture, relative to a package under
// core/internal. Its files seed the fuzz corpora.
const FixtureDir = "../../../cli/testdata/fixtures/credential-file-group-readable/input"

// Seed reads a file of the seed fixture, failing the test if it is missing.
func Seed(tb testing.TB, name string) []byte {
	tb.Helper()
	b, err := os.ReadFile(filepath.Join(FixtureDir, name))
	if err != nil {
		tb.Fatal(err)
	}
	return b
}

// JSONDepth returns the nesting depth of content if it is valid JSON, and
// false if it is not.
func JSONDepth(content []byte) (depth int, ok bool) {
	dec := json.NewDecoder(bytes.NewReader(content))
	cur := 0
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return depth, true
		}
		if err != nil {
			return 0, false
		}
		if d, isDelim := tok.(json.Delim); isDelim {
			switch d {
			case '{', '[':
				cur++
				depth = max(depth, cur)
			default:
				cur--
			}
		}
	}
}

// YAMLDepth returns the nesting depth of content if it is a valid YAML
// document, and false if it is not.
func YAMLDepth(content []byte) (depth int, ok bool) {
	var v any
	if err := yaml.Unmarshal(content, &v); err != nil {
		return 0, false
	}
	return valueDepth(v), true
}

func valueDepth(v any) int {
	deepest := 0
	switch v := v.(type) {
	case map[string]any:
		for _, c := range v {
			deepest = max(deepest, valueDepth(c))
		}
	case map[any]any:
		for _, c := range v {
			deepest = max(deepest, valueDepth(c))
		}
	case []any:
		for _, c := range v {
			deepest = max(deepest, valueDepth(c))
		}
	default:
		return 0
	}
	return deepest + 1
}
