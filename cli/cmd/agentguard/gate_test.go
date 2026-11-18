package main_test

import (
	"path/filepath"
	"strings"
	"testing"
)

// The Deployment Gate: --fail-on makes analyze exit with status 3 when a
// Reach Path has at least the given severity. Status 1 stays "the analysis
// failed" and 2 "bad usage", so a CI job can tell a blocked deployment from
// a broken run.

func fixtureInput(name string) string {
	return filepath.Join(fixturesDir, name, "input")
}

// criticalFixture has Reach Paths of severity critical, high, medium, and
// unknown.
const criticalFixture = "mcp-shell-to-s3-destroy-data"

// unknownOnlyFixture has Reach Paths, but every one has an unknown severity.
const unknownOnlyFixture = "aws-scoped-read-only-no-destroy-data"

func TestFailOnExitsWithStatus3WhenAReachPathMeetsTheThreshold(t *testing.T) {
	for _, threshold := range []string{"low", "medium", "high", "critical"} {
		stdout, stderr, code := runCLI(t, "analyze", "--now", fixtureNow, "--fail-on", threshold, fixtureInput(criticalFixture))
		if code != 3 {
			t.Errorf("--fail-on %s: want exit status 3, got %d (stderr: %s)", threshold, code, stderr)
		}
		if stdout == "" {
			t.Errorf("--fail-on %s: the report must still be printed when the gate fails", threshold)
		}
		// A CI log that shows only stderr must still say why the job failed.
		if want := "Deployment Gate failed: a Reach Path has severity " + threshold + " or above"; !strings.Contains(stderr, want) {
			t.Errorf("--fail-on %s: stderr must say %q, got %q", threshold, want, stderr)
		}
	}
}

func TestFailOnIsOffByDefault(t *testing.T) {
	_, stderr, code := runCLI(t, "analyze", "--now", fixtureNow, fixtureInput(criticalFixture))
	if code != 0 {
		t.Errorf("without --fail-on, Reach Paths must not fail the run: exit %d (stderr: %s)", code, stderr)
	}
}

func TestFailOnPassesWhenNoReachPathMeetsTheThreshold(t *testing.T) {
	// No Reach Paths at all.
	_, stderr, code := runCLI(t, "analyze", "--now", fixtureNow, "--fail-on", "low", fixtureInput("aws-explicit-deny-overrides-allow"))
	if code != 0 {
		t.Errorf("no Reach Paths: want exit status 0, got %d (stderr: %s)", code, stderr)
	}
	// Reach Paths whose severity is unknown never meet a threshold: the
	// gate does not guess.
	_, stderr, code = runCLI(t, "analyze", "--now", fixtureNow, "--fail-on", "low", fixtureInput(unknownOnlyFixture))
	if code != 0 {
		t.Errorf("unknown severity must not meet --fail-on low: exit %d (stderr: %s)", code, stderr)
	}
}

func TestFailOnRejectsAnUnknownSeverity(t *testing.T) {
	for _, value := range []string{"urgent", "unknown", ""} {
		stdout, _, code := runCLI(t, "analyze", "--fail-on", value, fixtureInput(criticalFixture))
		if code != 2 || stdout != "" {
			t.Errorf("--fail-on %q: want exit status 2 and no output, got %d and %q", value, code, stdout)
		}
	}
}

func TestAnErrorStillExitsWithStatus1UnderTheGate(t *testing.T) {
	_, _, code := runCLI(t, "analyze", "--now", fixtureNow, "--fail-on", "low", fixtureInput("mcp-malformed-json"))
	if code != 1 {
		t.Errorf("a rejected input must exit 1, got %d", code)
	}
}
