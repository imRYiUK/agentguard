// Command agentguard is the AgentGuard CLI. It is a thin shell over the core
// analysis library.
//
// Usage:
//
//	agentguard analyze [--now TIME] [--stale-after DURATION]
//	                   [--format text|json] [--fail-on SEVERITY] <dir>
//
// analyze reads the Agent Manifest <dir>/agentguard.yaml, the agent
// configuration files and Snapshots it refers to, and prints what it found.
//
// --format chooses the output: text (the default) is a summary for a person,
// json is the whole result for a program. Identical inputs, with the same
// --now, give byte-identical output in either.
//
// --fail-on (low, medium, high, or critical) makes the command a Deployment
// Gate: it exits with status 3 when a Reach Path has at least that severity.
// Reach Paths of unknown severity never meet it. Without --fail-on, Reach
// Paths do not affect the exit status.
//
// --now (RFC 3339, default: the current time) is the time Snapshot ages are
// measured against; fixing it makes a result reproducible. --stale-after (a
// Go duration such as 168h, default 7 days) is the age past which a Snapshot
// is a Stale Snapshot.
//
// Exit status: 0 on success, 1 when the analysis failed, 2 on a usage error,
// 3 when the Deployment Gate failed.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	analysisv1 "github.com/imRYiUK/agentguard/proto/gen/go/agentguard/analysis/v1"

	"github.com/imRYiUK/agentguard/cli/internal/report"
	"github.com/imRYiUK/agentguard/core/analysis"
)

const usage = "usage: agentguard analyze [--now TIME] [--stale-after DURATION] [--format text|json] [--fail-on SEVERITY] <dir>"

// Exit statuses. A CI job can tell a deployment the gate blocked from an
// analysis that broke.
const (
	exitOK       = 0
	exitError    = 1 // the analysis failed, or its output could not be written
	exitUsage    = 2 // the command line is wrong
	exitGateFail = 3 // a Reach Path meets the --fail-on severity
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "analyze" {
		fmt.Fprintln(stderr, usage)
		return exitUsage
	}
	flags := flag.NewFlagSet("analyze", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	nowFlag := flags.String("now", "", "")
	staleAfter := flags.Duration("stale-after", analysis.DefaultStalenessThreshold, "")
	format := "text"
	flags.Func("format", "", func(value string) error {
		if value != "text" && value != "json" {
			return fmt.Errorf("%q is not an output format; use text or json", value)
		}
		format = value
		return nil
	})
	var failOn analysisv1.Severity
	var failOnName string
	gated := false
	flags.Func("fail-on", "", func(value string) error {
		severity, err := report.ParseThreshold(value)
		failOn, failOnName, gated = severity, value, err == nil
		return err
	})
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 1 {
		if err != nil {
			fmt.Fprintln(stderr, "agentguard:", err)
		}
		fmt.Fprintln(stderr, usage)
		return exitUsage
	}
	in := analysis.Input{Files: os.DirFS(flags.Arg(0)), StalenessThreshold: *staleAfter}
	if *staleAfter <= 0 {
		fmt.Fprintln(stderr, "agentguard: --stale-after must be positive")
		return exitUsage
	}
	if *nowFlag != "" {
		now, err := time.Parse(time.RFC3339, *nowFlag)
		if err != nil {
			fmt.Fprintf(stderr, "agentguard: --now must be an RFC 3339 time such as 2026-11-17T12:00:00Z: %v\n", err)
			return exitUsage
		}
		in.Now = now
	}
	result, err := analysis.Analyze(in)
	if err != nil {
		fmt.Fprintln(stderr, "agentguard:", err)
		return exitError
	}
	var out []byte
	if format == "json" {
		if out, err = analysis.MarshalJSON(result); err != nil {
			fmt.Fprintln(stderr, "agentguard:", err)
			return exitError
		}
	} else {
		out = report.Text(result)
	}
	if _, err := stdout.Write(out); err != nil {
		return exitError
	}
	if gated && report.MeetsThreshold(result, failOn) {
		fmt.Fprintf(stderr, "agentguard: Deployment Gate failed: a Reach Path has severity %s or above\n", failOnName)
		return exitGateFail
	}
	return exitOK
}
