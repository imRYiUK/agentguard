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

// declaredServer is an MCP server a configuration declares and no settings
// file disables.
type declaredServer struct {
	name     string
	source   string
	location string
	server   mcpServer
}

// enabledServers returns the MCP servers declared across the MCP
// configurations, leaving out those a Claude Code settings file disables. The
// result is ordered by source, then server name.
func enabledServers(mcpConfigs, settings []File) ([]declaredServer, error) {
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

	var servers []declaredServer
	for _, f := range mcpConfigs {
		var c mcpConfig
		if err := limits.CheckJSON(f.Content, limits.MaxConfigBytes); err != nil {
			return nil, fmt.Errorf("%s: invalid MCP configuration: %w", f.Source, err)
		}
		if err := json.Unmarshal(f.Content, &c); err != nil {
			return nil, fmt.Errorf("%s: invalid MCP configuration: %w", f.Source, err)
		}
		for _, name := range sortedKeys(c.MCPServers) {
			if slices.Contains(disabled, name) {
				continue
			}
			servers = append(servers, declaredServer{
				name:     name,
				source:   f.Source,
				location: jsonpath.Key("$.mcpServers", name),
				server:   c.MCPServers[name],
			})
		}
	}
	return servers, nil
}

// ShellTools returns the shell Tools declared across the MCP configurations,
// leaving out servers that a Claude Code settings file disables. The result
// is ordered by source, then server name.
func ShellTools(mcpConfigs, settings []File) ([]ShellTool, error) {
	servers, err := enabledServers(mcpConfigs, settings)
	if err != nil {
		return nil, err
	}
	var tools []ShellTool
	for _, s := range servers {
		if packageIndex(s.server, shellServers) >= 0 {
			tools = append(tools, ShellTool{Server: s.name, Source: s.source, Location: s.location})
		}
	}
	return tools, nil
}

// FilesystemTool is a filesystem MCP server given access to a broad part of
// the host.
type FilesystemTool struct {
	// Server is the MCP server's name in the MCP configuration.
	Server string
	// Root is the directory as the configuration writes it.
	Root string
	// Source and Location say where the directory is written.
	Source   string
	Location string
}

// filesystemServers lists MCP server packages that give the agent access to
// the directories named in their arguments.
var filesystemServers = []string{
	"@modelcontextprotocol/server-filesystem",
}

// broadRoots are the directories that cover the whole host or every user's
// files. A configuration that names a narrower directory is not reported:
// whether it is too broad depends on what the host keeps there, and AgentGuard
// does not guess that.
var broadRoots = []string{"/", "/home", "/root", "/Users", "~", "$HOME", "${HOME}"}

// BroadFilesystemTools returns the filesystem Tools declared across the MCP
// configurations that are given a broad directory, one for each such
// directory, leaving out servers that a Claude Code settings file disables.
// The result is ordered by source, server name, then position.
func BroadFilesystemTools(mcpConfigs, settings []File) ([]FilesystemTool, error) {
	servers, err := enabledServers(mcpConfigs, settings)
	if err != nil {
		return nil, err
	}
	var tools []FilesystemTool
	for _, s := range servers {
		at := packageIndex(s.server, filesystemServers)
		if at < 0 {
			continue
		}
		// The directories are the arguments after the package. Flags are not
		// directories.
		for i, arg := range s.server.Args {
			if i+1 <= at || strings.HasPrefix(arg, "-") || !slices.Contains(broadRoots, cleanRoot(arg)) {
				continue
			}
			tools = append(tools, FilesystemTool{
				Server:   s.name,
				Root:     arg,
				Source:   s.source,
				Location: fmt.Sprintf("%s.args[%d]", s.location, i),
			})
		}
	}
	return tools, nil
}

// cleanRoot drops the trailing slashes of a directory, keeping the root
// directory itself.
func cleanRoot(dir string) string {
	if trimmed := strings.TrimRight(dir, "/"); trimmed != "" {
		return trimmed
	}
	if dir != "" {
		return "/"
	}
	return ""
}

// packageIndex returns the position of the first of packages in the server's
// command and arguments, counting the command as position 0 and the first
// argument as 1, optionally with a version pin. It is -1 when the server runs
// none of them.
func packageIndex(s mcpServer, packages []string) int {
	for i, word := range append([]string{path.Base(s.Command)}, s.Args...) {
		for _, pkg := range packages {
			if word == pkg || strings.HasPrefix(word, pkg+"@") || strings.HasPrefix(word, pkg+"==") {
				return i
			}
		}
	}
	return -1
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
