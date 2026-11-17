package manifest_test

import (
	"strings"
	"testing"

	"github.com/imRYiUK/agentguard/core/internal/fuzzutil"
	"github.com/imRYiUK/agentguard/core/internal/limits"
	"github.com/imRYiUK/agentguard/core/internal/manifest"
)

// FuzzParse checks that Parse never panics and always enforces its limits,
// whatever the input.
func FuzzParse(f *testing.F) {
	f.Add(fuzzutil.Seed(f, "agentguard.yaml"))
	f.Add([]byte(""))
	f.Add([]byte("# only a comment\n"))
	f.Add([]byte("version: 1\nagent: &a {name: x}\nenvironments: *a\n"))
	f.Add([]byte("version: 1\nresourceSensitivity: " + strings.Repeat("[", 40) + strings.Repeat("]", 40)))
	f.Add([]byte("version: 1\nagent:\n  name: a\nenvironments:\n  - name: h\n    type: aws\n    identity:\n      accountId: 123456789012\n    snapshot: s.json\n"))
	f.Add([]byte(strings.Repeat("- a\n", 100)))
	f.Add([]byte(strings.Repeat("[", 20000)))
	f.Add([]byte("# " + strings.Repeat("a", limits.MaxConfigBytes) + "\n"))

	f.Fuzz(func(t *testing.T, content []byte) {
		m, err := manifest.Parse("agentguard.yaml", content)
		if len(content) > limits.MaxConfigBytes && err == nil {
			t.Fatalf("accepted %d bytes; the limit is %d", len(content), limits.MaxConfigBytes)
		}
		if depth, ok := fuzzutil.YAMLDepth(content); ok && depth > limits.MaxDepth && err == nil {
			t.Fatalf("accepted a document nested %d levels; the limit is %d", depth, limits.MaxDepth)
		}
		if err != nil {
			return
		}
		if m.Version != manifest.SchemaVersion || m.Agent.Name == "" || len(m.Environments) == 0 {
			t.Fatalf("accepted an incomplete manifest: %+v", m)
		}
		for name, n := range map[string]int{
			"environments":        len(m.Environments),
			"declaredBindings":    len(m.DeclaredBindings),
			"resourceSensitivity": len(m.ResourceSensitivities),
			"claudeCodeSettings":  len(m.Agent.ClaudeCodeSettings),
			"mcp":                 len(m.Agent.MCP),
		} {
			if n > limits.MaxListLength {
				t.Fatalf("accepted %d %s entries; the limit is %d", n, name, limits.MaxListLength)
			}
		}
	})
}
