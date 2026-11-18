// Command agentguard-collector is the AgentGuard Collector. It reads the
// environment it runs in, read-only, and writes a Snapshot.
//
// Usage:
//
//	agentguard-collector linux [--out FILE]
//	agentguard-collector aws [--profile NAME] [--out FILE]
//
// linux collects a Snapshot of this Linux host as the user running the
// command, which is taken to be the user the agent runs as. It needs no root.
//
// aws collects a Snapshot of the AWS account behind the credentials found on
// this host, the way the AWS CLI finds them (environment variables, the
// shared credentials and config files, instance or container credentials;
// --profile names a profile). It records the Identity those credentials
// resolve to and that Identity's identity-based policies, and makes read-only
// AWS calls only.
//
// The Snapshot is Protobuf canonical JSON, written to FILE or, without
// --out, to standard output. It never holds a secret value.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/imRYiUK/agentguard/collector/aws"
	"github.com/imRYiUK/agentguard/collector/host"
	"github.com/imRYiUK/agentguard/collector/linux"
)

// version is the Collector's version. A release build sets it with
// -ldflags "-X main.version=...".
var version = "0.1.0-dev"

const usage = "usage: agentguard-collector linux [--out FILE]\n" +
	"       agentguard-collector aws [--profile NAME] [--out FILE]"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || (args[0] != "linux" && args[0] != "aws") {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	command := args[0]
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	out := flags.String("out", "", "")
	var profile *string
	if command == "aws" {
		profile = flags.String("profile", "", "")
	}
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
		if err != nil {
			fmt.Fprintln(stderr, "agentguard-collector:", err)
		}
		fmt.Fprintln(stderr, usage)
		return 2
	}

	fail := func(err error) int {
		fmt.Fprintln(stderr, "agentguard-collector:", err)
		return 1
	}
	id, err := snapshotID(command)
	if err != nil {
		return fail(err)
	}
	var content []byte
	switch command {
	case "linux":
		snap, err := linux.Collect(host.OS{}, linux.Options{Version: version, Now: time.Now(), SnapshotID: id})
		if err != nil {
			return fail(err)
		}
		if content, err = linux.MarshalJSON(snap); err != nil {
			return fail(err)
		}
	case "aws":
		ctx := context.Background()
		api, err := aws.LoadSDK(ctx, *profile)
		if err != nil {
			return fail(err)
		}
		snap, err := aws.Collect(ctx, api, aws.Options{Version: version, Now: time.Now(), SnapshotID: id})
		if err != nil {
			return fail(err)
		}
		if content, err = aws.MarshalJSON(snap); err != nil {
			return fail(err)
		}
	}

	if *out == "" {
		if _, err := stdout.Write(content); err != nil {
			return 1
		}
		return 0
	}
	if err := os.WriteFile(*out, content, 0o600); err != nil {
		return fail(err)
	}
	return 0
}

// snapshotID returns a random Snapshot ID.
func snapshotID(command string) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "snap-" + command + "-" + hex.EncodeToString(b), nil
}
