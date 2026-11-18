package main_test

import (
	"bytes"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const staleFixture = "../../testdata/fixtures/credential-file-group-readable/input"

func runCLI(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	var out, errOut bytes.Buffer
	cmd := exec.Command(binary, args...)
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exit):
		code = exit.ExitCode()
	default:
		t.Fatal(err)
	}
	return out.String(), errOut.String(), code
}

func TestAnalyzeFlagsSetTheClockAndTheStalenessThreshold(t *testing.T) {
	dir := filepath.Clean(staleFixture)
	out, stderr, code := runCLI(t, "analyze", "--format", "json", "--now", "2026-11-17T12:00:00Z", "--stale-after", "1h", dir)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	// Two hours after collection with a one-hour threshold: both stale.
	if got := strings.Count(out, `"stale": true`); got != 2 {
		t.Errorf("want 2 stale Snapshots, got %d in\n%s", got, out)
	}
	out, _, _ = runCLI(t, "analyze", "--format", "json", "--now", "2026-11-17T12:00:00Z", dir)
	if strings.Contains(out, `"stale": true`) {
		t.Errorf("by default, a Snapshot two hours old is not stale:\n%s", out)
	}
}

func TestAnalyzeRejectsBadFlagValues(t *testing.T) {
	dir := filepath.Clean(staleFixture)
	for _, args := range [][]string{
		{"analyze", "--now", "yesterday", dir},
		{"analyze", "--stale-after", "-1h", dir},
		{"analyze", "--stale-after", "soon", dir},
		{"analyze", "--bogus", dir},
		{"analyze"},
	} {
		stdout, _, code := runCLI(t, args...)
		if code != 2 || stdout != "" {
			t.Errorf("%v: want exit status 2 and no output, got %d and %q", args, code, stdout)
		}
	}
}
