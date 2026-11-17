package main_test

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// The golden-fixture harness. Each folder under testdata/fixtures holds an
// input/ folder and the expected CLI output for it. The test runs the real
// CLI binary over input/ and compares its stdout with the expected file
// byte for byte.
//
// Regenerate expected files after an intended change with:
//
//	go test ./cmd/agentguard -update
//
// and review the diff before committing it.
var update = flag.Bool("update", false, "rewrite the expected output of every fixture")

const fixturesDir = "../../testdata/fixtures"

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
			expectedPath := filepath.Join(fixture, "expected.json")

			var stdout, stderr bytes.Buffer
			cmd := exec.Command(binary, "analyze", filepath.Join(fixture, "input"))
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			if err := cmd.Run(); err != nil {
				t.Fatalf("agentguard analyze: %v\nstderr:\n%s", err, stderr.String())
			}

			if *update {
				if err := os.WriteFile(expectedPath, stdout.Bytes(), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}

			expected, err := os.ReadFile(expectedPath)
			if err != nil {
				t.Fatalf("reading expected output (run with -update to create it): %v", err)
			}
			if !bytes.Equal(stdout.Bytes(), expected) {
				t.Errorf("output differs from %s (run with -update to accept)\n--- got ---\n%s\n--- want ---\n%s",
					expectedPath, stdout.String(), expected)
			}
		})
	}
}
