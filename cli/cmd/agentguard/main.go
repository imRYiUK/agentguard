// Command agentguard is the AgentGuard CLI. It is a thin shell over the core
// analysis library.
//
// Usage:
//
//	agentguard analyze [-deployment name] <dir>
//
// analyze reads an Analysis Input from dir and prints the Reach Paths as
// JSON. The folder layout is:
//
//	<dir>/.claude/settings.json   Claude Code settings (optional)
//	<dir>/.mcp.json               MCP configuration (optional)
//	<dir>/snapshots/*.json        Snapshots in Protobuf canonical JSON
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"github.com/imRYiUK/agentguard/core/analysis"
)

const usage = "usage: agentguard analyze [-deployment name] <dir>"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "analyze" {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	flags := flag.NewFlagSet("analyze", flag.ContinueOnError)
	flags.SetOutput(stderr)
	deployment := flags.String("deployment", "default", "name of the Agent Deployment")
	if err := flags.Parse(args[1:]); err != nil {
		return 2
	}
	if flags.NArg() != 1 {
		fmt.Fprintln(stderr, usage)
		return 2
	}

	input, err := readInput(flags.Arg(0), *deployment)
	if err != nil {
		fmt.Fprintln(stderr, "agentguard:", err)
		return 1
	}
	result, err := analysis.Analyze(input)
	if err != nil {
		fmt.Fprintln(stderr, "agentguard:", err)
		return 1
	}
	out, err := analysis.MarshalJSON(result)
	if err != nil {
		fmt.Fprintln(stderr, "agentguard:", err)
		return 1
	}
	if _, err := stdout.Write(out); err != nil {
		return 1
	}
	return 0
}

// readInput loads the files of an Analysis Input from dir. Evidence names
// each file by its path relative to dir.
func readInput(dir, deployment string) (analysis.Input, error) {
	input := analysis.Input{AgentDeployment: deployment}
	var err error
	if input.ClaudeCodeSettings, err = readOptional(dir, ".claude/settings.json"); err != nil {
		return input, err
	}
	if input.MCPConfigs, err = readOptional(dir, ".mcp.json"); err != nil {
		return input, err
	}
	matches, err := filepath.Glob(filepath.Join(dir, "snapshots", "*.json"))
	if err != nil {
		return input, err
	}
	slices.Sort(matches)
	for _, match := range matches {
		f, err := readFile(dir, match)
		if err != nil {
			return input, err
		}
		input.Snapshots = append(input.Snapshots, f)
	}
	return input, nil
}

func readOptional(dir, rel string) ([]analysis.File, error) {
	f, err := readFile(dir, filepath.Join(dir, rel))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return []analysis.File{f}, nil
}

func readFile(dir, path string) (analysis.File, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return analysis.File{}, err
	}
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		return analysis.File{}, err
	}
	return analysis.File{Source: filepath.ToSlash(rel), Content: content}, nil
}
