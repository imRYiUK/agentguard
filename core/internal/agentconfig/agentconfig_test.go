package agentconfig_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/imRYiUK/agentguard/core/internal/agentconfig"
)

func broad(t *testing.T, mcp, settings string) []string {
	t.Helper()
	tools, err := agentconfig.BroadFilesystemTools(
		[]agentconfig.File{{Source: ".mcp.json", Content: []byte(mcp)}},
		[]agentconfig.File{{Source: ".claude/settings.json", Content: []byte(settings)}},
	)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, tool := range tools {
		out = append(out, fmt.Sprintf("%s %s %s %s", tool.Server, tool.Root, tool.Source, tool.Location))
	}
	return out
}

func server(command string, args ...string) string {
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = fmt.Sprintf("%q", a)
	}
	return fmt.Sprintf(`{"mcpServers":{"files":{"command":%q,"args":[%s]}}}`, command, strings.Join(quoted, ","))
}

func TestBroadFilesystemToolsFindsServersGivenABroadDirectory(t *testing.T) {
	for _, root := range []string{"/", "/home", "/home/", "/root", "/Users", "~", "~/", "$HOME", "${HOME}"} {
		t.Run(root, func(t *testing.T) {
			got := broad(t, server("npx", "-y", "@modelcontextprotocol/server-filesystem", root), "{}")
			want := fmt.Sprintf("files %s .mcp.json $.mcpServers.files.args[2]", root)
			if len(got) != 1 || got[0] != want {
				t.Errorf("got %q, want [%q]", got, want)
			}
		})
	}
}

func TestBroadFilesystemToolsIgnoresNarrowDirectories(t *testing.T) {
	for _, root := range []string{"/srv/app/data", "/home/deploy/project", "./docs", "/tmp/work", "~/project"} {
		if got := broad(t, server("npx", "-y", "@modelcontextprotocol/server-filesystem", root), "{}"); len(got) != 0 {
			t.Errorf("%s: want no finding, got %q", root, got)
		}
	}
}

func TestBroadFilesystemToolsReportsEachBroadDirectory(t *testing.T) {
	got := broad(t, server("npx", "@modelcontextprotocol/server-filesystem@2025.1.14", "/srv/data", "/", "~"), "{}")
	want := []string{
		"files / .mcp.json $.mcpServers.files.args[2]",
		"files ~ .mcp.json $.mcpServers.files.args[3]",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestBroadFilesystemToolsRecognizesOnlyTheFilesystemServer(t *testing.T) {
	if got := broad(t, server("uvx", "mcp-server-fetch", "/"), "{}"); len(got) != 0 {
		t.Errorf("another server given / is not a filesystem Tool, got %q", got)
	}
	if got := broad(t, server("node", "/opt/server-filesystem/index.js", "/"), "{}"); len(got) != 0 {
		t.Errorf("a path that only resembles the package is not it, got %q", got)
	}
}

func TestBroadFilesystemToolsLeavesOutDisabledServers(t *testing.T) {
	mcp := server("npx", "@modelcontextprotocol/server-filesystem", "/")
	if got := broad(t, mcp, `{"disabledMcpjsonServers":["files"]}`); len(got) != 0 {
		t.Errorf("a disabled server is not a Tool, got %q", got)
	}
}

func TestBroadFilesystemToolsRejectsAMalformedConfig(t *testing.T) {
	_, err := agentconfig.BroadFilesystemTools([]agentconfig.File{{Source: ".mcp.json", Content: []byte("{")}}, nil)
	if err == nil || !strings.Contains(err.Error(), ".mcp.json: invalid MCP configuration") {
		t.Errorf("want an invalid MCP configuration error, got %v", err)
	}
}
