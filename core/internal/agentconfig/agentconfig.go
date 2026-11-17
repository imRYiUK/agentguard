// Package agentconfig reads agent-client configuration (Claude Code settings
// and MCP configuration) and recognizes the Tools it declares.
package agentconfig

import (
	"encoding/json"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/imRYiUK/agentguard/core/internal/jsonpath"
	"github.com/imRYiUK/agentguard/core/internal/limits"
)

// File is one configuration file and the name it is reported under.
type File struct {
	Source  string
	Content []byte
}

// ShellTool is an MCP server that gives the agent unrestricted command
// execution.
type ShellTool struct {
	// Server is the MCP server's name in the MCP configuration.
	Server string
	// Source and Location say where the server is declared.
	Source   string
	Location string
}

// shellServers lists MCP server packages known to run arbitrary shell
// commands. A server is recognized when its command or one of its arguments
// names one of these packages, optionally with a version pin.
var shellServers = []string{
	"mcp-shell-server",
	"mcp-server-commands",
	"@wonderwhy-er/desktop-commander",
}

type mcpConfig struct {
	MCPServers map[string]mcpServer `json:"mcpServers"`
}

type mcpServer struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
}

type claudeSettings struct {
	DisabledMCPJSONServers []string `json:"disabledMcpjsonServers"`
}

// ShellTools returns the shell Tools declared across the MCP configurations,
// leaving out servers that a Claude Code settings file disables. The result
// is ordered by source, then server name.
func ShellTools(mcpConfigs, settings []File) ([]ShellTool, error) {
	var disabled []string
	for _, f := range settings {
		var s claudeSettings
		if err := limits.CheckJSON(f.Content, limits.MaxConfigBytes); err != nil {
			return nil, fmt.Errorf("%s: invalid Claude Code settings: %w", f.Source, err)
		}
		if err := json.Unmarshal(f.Content, &s); err != nil {
			return nil, fmt.Errorf("%s: invalid Claude Code settings: %w", f.Source, err)
		}
		disabled = append(disabled, s.DisabledMCPJSONServers...)
	}

	var tools []ShellTool
	for _, f := range mcpConfigs {
		var c mcpConfig
		if err := limits.CheckJSON(f.Content, limits.MaxConfigBytes); err != nil {
			return nil, fmt.Errorf("%s: invalid MCP configuration: %w", f.Source, err)
		}
		if err := json.Unmarshal(f.Content, &c); err != nil {
			return nil, fmt.Errorf("%s: invalid MCP configuration: %w", f.Source, err)
		}
		for _, name := range sortedKeys(c.MCPServers) {
			if slices.Contains(disabled, name) || !isShellServer(c.MCPServers[name]) {
				continue
			}
			tools = append(tools, ShellTool{
				Server:   name,
				Source:   f.Source,
				Location: jsonpath.Key("$.mcpServers", name),
			})
		}
	}
	return tools, nil
}

func isShellServer(s mcpServer) bool {
	for _, word := range append([]string{path.Base(s.Command)}, s.Args...) {
		for _, pkg := range shellServers {
			if word == pkg || strings.HasPrefix(word, pkg+"@") || strings.HasPrefix(word, pkg+"==") {
				return true
			}
		}
	}
	return false
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
