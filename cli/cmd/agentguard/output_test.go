package main_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFormatDefaultsToText(t *testing.T) {
	dir := fixtureInput(criticalFixture)
	def, stderr, code := runCLI(t, "analyze", "--now", fixtureNow, dir)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	text, _, _ := runCLI(t, "analyze", "--now", fixtureNow, "--format", "text", dir)
	if def != text {
		t.Errorf("the default format must be text:\n%s", def)
	}
	if json.Valid([]byte(def)) {
		t.Errorf("text output must not be JSON:\n%s", def)
	}
}

func TestFormatJSONIsMachineReadable(t *testing.T) {
	out, stderr, code := runCLI(t, "analyze", "--now", fixtureNow, "--format", "json", fixtureInput(criticalFixture))
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	var decoded struct {
		ReachPaths []struct{ Severity string }
	}
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("--format json must print one JSON document: %v\n%s", err, out)
	}
	if len(decoded.ReachPaths) == 0 {
		t.Errorf("want Reach Paths in the JSON, got\n%s", out)
	}
}

func TestFormatRejectsAnUnknownFormat(t *testing.T) {
	for _, value := range []string{"yaml", "TEXT", ""} {
		stdout, _, code := runCLI(t, "analyze", "--format", value, fixtureInput(criticalFixture))
		if code != 2 || stdout != "" {
			t.Errorf("--format %q: want exit status 2 and no output, got %d and %q", value, code, stdout)
		}
	}
}

func TestTheGateAppliesToBothFormats(t *testing.T) {
	for _, format := range []string{"text", "json"} {
		_, _, code := runCLI(t, "analyze", "--now", fixtureNow, "--format", format, "--fail-on", "critical", fixtureInput(criticalFixture))
		if code != 3 {
			t.Errorf("--format %s: want exit status 3, got %d", format, code)
		}
	}
}

// Identical inputs give byte-identical output. Each fixture is analyzed
// several times, as separate processes, in both formats; Go randomizes map
// iteration per process, so an output that depends on it differs between runs.
func TestIdenticalInputsGiveByteIdenticalOutput(t *testing.T) {
	entries, err := os.ReadDir(fixturesDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(fixturesDir, entry.Name(), "expected-error.txt")); err == nil {
			continue // rejected inputs print nothing to stdout
		}
		for _, format := range []string{"text", "json"} {
			var first string
			for run := range 5 {
				out, stderr, code := runCLI(t, "analyze", "--now", fixtureNow, "--format", format, fixtureInput(entry.Name()))
				if code != 0 {
					t.Fatalf("%s %s: exit %d: %s", entry.Name(), format, code, stderr)
				}
				if run == 0 {
					first = out
				} else if out != first {
					t.Fatalf("%s %s: run %d differs from run 0", entry.Name(), format, run)
				}
			}
		}
	}
}

// The output does not depend on where the input is: the same fixture copied
// to another folder prints the same bytes, so a CI job's checkout path never
// leaks into a result.
func TestOutputDoesNotDependOnTheInputPath(t *testing.T) {
	src := fixtureInput(criticalFixture)
	copyDir := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.CopyFS(copyDir, os.DirFS(src)); err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"text", "json"} {
		want, _, _ := runCLI(t, "analyze", "--now", fixtureNow, "--format", format, src)
		got, _, _ := runCLI(t, "analyze", "--now", fixtureNow, "--format", format, copyDir)
		if got != want || strings.Contains(got, copyDir) {
			t.Errorf("--format %s: the output depends on the input's path", format)
		}
	}
}
