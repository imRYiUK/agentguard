// Command agentguard is the AgentGuard CLI. It is a thin shell over the core
// analysis library.
//
// Usage:
//
//	agentguard analyze <dir>
//
// analyze reads the Agent Manifest <dir>/agentguard.yaml, the agent
// configuration files and Snapshots it refers to, and prints the Reach Paths
// as JSON.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/imRYiUK/agentguard/core/analysis"
)

const usage = "usage: agentguard analyze <dir>"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) != 2 || args[0] != "analyze" {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	result, err := analysis.Analyze(analysis.Input{Files: os.DirFS(args[1])})
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
