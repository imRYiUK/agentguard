package main_test

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// The golden-fixture harness. Each folder under testdata/fixtures holds an
// input/ folder and the expected CLI output for it. The test runs the real
// CLI binary over input/ and compares the output with the expected file byte
// for byte.
//
// A fixture that expects Reach Paths has an expected.json holding the
// stdout. A fixture whose input must be rejected has an expected-error.txt
// holding the stderr; the CLI must then exit with status 1 and print nothing
// to stdout.
//
// Regenerate expected files after an intended change with:
//
//	go test ./cmd/agentguard -update
//
// and review the diff before committing it.
var update = flag.Bool("update", false, "rewrite the expected output of every fixture")

const fixturesDir = "../../testdata/fixtures"

// fixtureNow is the time the fixtures are analyzed at, so the age of their
// Snapshots, and so the result, never depends on the real clock. It is a
// couple of hours after the fixtures' Snapshots were collected.
const fixtureNow = "2026-11-17T12:00:00Z"

var binary string

func TestMain(m *testing.M) {
	flag.Parse()
	dir, err := os.MkdirTemp("", "agentguard-cli-test")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	binary = filepath.Join(dir, "agentguard")
	build := exec.Command("go", "build", "-o", binary, ".")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "building the CLI:", err)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func TestAnalyzeFixtures(t *testing.T) {
	entries, err := os.ReadDir(fixturesDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("no fixtures found")
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		t.Run(entry.Name(), func(t *testing.T) {
			fixture := filepath.Join(fixturesDir, entry.Name())
			expectedJSON := filepath.Join(fixture, "expected.json")
			expectedError := filepath.Join(fixture, "expected-error.txt")

			var stdout, stderr bytes.Buffer
			cmd := exec.Command(binary, "analyze", "--now", fixtureNow, filepath.Join(fixture, "input"))
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			runErr := cmd.Run()

			rejected := fileExists(expectedError)
			if *update {
				rejected = runErr != nil
			}
			var got, path string
			if rejected {
				var exit *exec.ExitError
				if !errors.As(runErr, &exit) || exit.ExitCode() != 1 {
					t.Fatalf("agentguard analyze: want exit status 1, got %v\nstderr:\n%s", runErr, stderr.String())
				}
				if stdout.Len() != 0 {
					t.Errorf("a rejected input must print nothing to stdout, got:\n%s", stdout.String())
				}
				got, path = stderr.String(), expectedError
			} else {
				if runErr != nil {
					t.Fatalf("agentguard analyze: %v\nstderr:\n%s", runErr, stderr.String())
				}
				got, path = stdout.String(), expectedJSON
			}

			if *update {
				if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}

			expected, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("reading expected output (run with -update to create it): %v", err)
			}
			if got != string(expected) {
				t.Errorf("output differs from %s (run with -update to accept)\n--- got ---\n%s\n--- want ---\n%s",
					path, got, expected)
			}
		})
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
