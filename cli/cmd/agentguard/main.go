// Command agentguard is the AgentGuard CLI. It is a thin shell over the core
// analysis library.
//
// Usage:
//
//	agentguard analyze [--now TIME] [--stale-after DURATION] <dir>
//
// analyze reads the Agent Manifest <dir>/agentguard.yaml, the agent
// configuration files and Snapshots it refers to, and prints the Reach Paths
// as JSON.
//
// --now (RFC 3339, default: the current time) is the time Snapshot ages are
// measured against; fixing it makes a result reproducible. --stale-after (a
// Go duration such as 168h, default 7 days) is the age past which a Snapshot
// is a Stale Snapshot.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/imRYiUK/agentguard/core/analysis"
)

const usage = "usage: agentguard analyze [--now TIME] [--stale-after DURATION] <dir>"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "analyze" {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	flags := flag.NewFlagSet("analyze", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	nowFlag := flags.String("now", "", "")
	staleAfter := flags.Duration("stale-after", analysis.DefaultStalenessThreshold, "")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 1 {
		if err != nil {
			fmt.Fprintln(stderr, "agentguard:", err)
		}
		fmt.Fprintln(stderr, usage)
		return 2
	}
	in := analysis.Input{Files: os.DirFS(flags.Arg(0)), StalenessThreshold: *staleAfter}
	if *staleAfter <= 0 {
		fmt.Fprintln(stderr, "agentguard: --stale-after must be positive")
		return 2
	}
	if *nowFlag != "" {
		now, err := time.Parse(time.RFC3339, *nowFlag)
		if err != nil {
			fmt.Fprintf(stderr, "agentguard: --now must be an RFC 3339 time such as 2026-11-17T12:00:00Z: %v\n", err)
			return 2
		}
		in.Now = now
	}
	result, err := analysis.Analyze(in)
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
