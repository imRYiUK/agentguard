package agentconfig_test

import (
	"strings"
	"testing"

	"github.com/imRYiUK/agentguard/core/internal/agentconfig"
	"github.com/imRYiUK/agentguard/core/internal/fuzzutil"
	"github.com/imRYiUK/agentguard/core/internal/limits"
)

// FuzzShellTools checks that reading an MCP configuration and a Claude Code
// settings file never panics and always enforces the limits, whatever the
// input.
func FuzzShellTools(f *testing.F) {
	mcp := fuzzutil.Seed(f, ".mcp.json")
	settings := fuzzutil.Seed(f, ".claude/settings.json")
	f.Add(mcp, settings)
	f.Add([]byte(`{"mcpServers":{"a":{"command":"npx","args":["mcp-shell-server@1"]}}}`), []byte(`{"disabledMcpjsonServers":["a"]}`))
	f.Add([]byte(`{"mcpServers":[]}`), []byte(`[]`))
	f.Add([]byte(`null`), []byte(``))
	f.Add([]byte(strings.Repeat("[", 40)+strings.Repeat("]", 40)), settings)
	f.Add([]byte(`{"mcpServers":{},"x":"`+strings.Repeat("a", limits.MaxConfigBytes)+`"}`), settings)
	f.Add(mcp, []byte(`{"x":"`+strings.Repeat("a", limits.MaxConfigBytes)+`"}`))
	f.Add(mcp, []byte(`{"x":`+strings.Repeat("[", 40)+strings.Repeat("]", 40)+`}`))

	f.Fuzz(func(t *testing.T, mcp, settings []byte) {
		_, err := agentconfig.ShellTools(
			[]agentconfig.File{{Source: ".mcp.json", Content: mcp}},
			[]agentconfig.File{{Source: "settings.json", Content: settings}},
		)
		for name, content := range map[string][]byte{"MCP configuration": mcp, "settings": settings} {
			if len(content) > limits.MaxConfigBytes && err == nil {
				t.Fatalf("accepted a %s of %d bytes; the limit is %d", name, len(content), limits.MaxConfigBytes)
			}
			if depth, ok := fuzzutil.JSONDepth(content); ok && depth > limits.MaxDepth && err == nil {
				t.Fatalf("accepted a %s nested %d levels; the limit is %d", name, depth, limits.MaxDepth)
			}
		}
	})
}
