// Command agentguard-collector is the AgentGuard Collector. It reads the host
// it runs on, read-only and without needing root, and writes a Snapshot.
//
// Usage:
//
//	agentguard-collector linux [--out FILE]
//
// linux collects a Snapshot of this Linux host as the user running the
// command, which is taken to be the user the agent runs as. The Snapshot is
// Protobuf canonical JSON, written to FILE or, without --out, to standard
// output. It never holds a secret value.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/imRYiUK/agentguard/collector/host"
	"github.com/imRYiUK/agentguard/collector/linux"
)

// version is the Collector's version. A release build sets it with
// -ldflags "-X main.version=...".
var version = "0.1.0-dev"

const usage = "usage: agentguard-collector linux [--out FILE]"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "linux" {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	flags := flag.NewFlagSet("linux", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	out := flags.String("out", "", "")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
		if err != nil {
			fmt.Fprintln(stderr, "agentguard-collector:", err)
		}
		fmt.Fprintln(stderr, usage)
		return 2
	}

	id, err := snapshotID()
	if err != nil {
		fmt.Fprintln(stderr, "agentguard-collector:", err)
		return 1
	}
	snap, err := linux.Collect(host.OS{}, linux.Options{Version: version, Now: time.Now(), SnapshotID: id})
	if err != nil {
		fmt.Fprintln(stderr, "agentguard-collector:", err)
		return 1
	}
	content, err := linux.MarshalJSON(snap)
	if err != nil {
		fmt.Fprintln(stderr, "agentguard-collector:", err)
		return 1
	}
	if *out == "" {
		if _, err := stdout.Write(content); err != nil {
			return 1
		}
		return 0
	}
	if err := os.WriteFile(*out, content, 0o600); err != nil {
		fmt.Fprintln(stderr, "agentguard-collector:", err)
		return 1
	}
	return 0
}

// snapshotID returns a random Snapshot ID.
func snapshotID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "snap-linux-" + hex.EncodeToString(b), nil
}
