package main_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

// These tests run the real Collector binary on the machine they run on.

var binary string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "agentguard-collector-test")
	if err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}
	binary = filepath.Join(dir, "agentguard-collector")
	build := exec.Command("go", "build", "-ldflags", "-X main.version=9.9.9-test", "-o", binary, ".")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		os.Stderr.WriteString("building the Collector: " + err.Error() + "\n")
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// hostIsIdentifiable reports whether this machine has a machine ID or an SSH
// host key, without which the Collector rightly refuses to run.
func hostIsIdentifiable() bool {
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id", "/etc/ssh/ssh_host_ed25519_key.pub", "/etc/ssh/ssh_host_ecdsa_key.pub", "/etc/ssh/ssh_host_rsa_key.pub"} {
		if _, err := os.ReadFile(p); err == nil {
			return true
		}
	}
	return false
}

func TestLinuxWritesASnapshotToStdout(t *testing.T) {
	if !hostIsIdentifiable() {
		t.Skip("this machine has no machine ID or readable SSH host key")
	}
	me, err := user.Current()
	if err != nil {
		t.Skip("cannot look up the current user")
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.Command(binary, "linux")
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("agentguard-collector linux: %v\nstderr:\n%s", err, stderr.String())
	}
	var snap struct {
		SchemaVersion    string `json:"schemaVersion"`
		SnapshotID       string `json:"snapshotId"`
		CollectorVersion string `json:"collectorVersion"`
		CollectedAt      string `json:"collectedAt"`
		CollectedBy      string `json:"collectedBy"`
		Linux            struct {
			AgentUser struct {
				UID json.Number `json:"uid"`
			} `json:"agentUser"`
		} `json:"linux"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &snap); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, stdout.String())
	}
	if snap.SchemaVersion != "1" || !strings.HasPrefix(snap.SnapshotID, "snap-linux-") || snap.CollectorVersion != "9.9.9-test" ||
		snap.CollectedAt == "" {
		t.Errorf("unexpected provenance: %+v", snap)
	}
	if snap.CollectedBy != me.Username && snap.CollectedBy != "uid-"+me.Uid {
		t.Errorf("collectedBy = %q, want %q", snap.CollectedBy, me.Username)
	}
}

func TestLinuxOutWritesAFileAndPrintsNothing(t *testing.T) {
	if !hostIsIdentifiable() {
		t.Skip("this machine has no machine ID or readable SSH host key")
	}
	out := filepath.Join(t.TempDir(), "linux.json")
	var stdout bytes.Buffer
	cmd := exec.Command(binary, "linux", "--out", out)
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(out)
	if err != nil || !json.Valid(content) {
		t.Fatalf("the --out file is missing or not JSON: %v", err)
	}
	if stdout.Len() != 0 {
		t.Errorf("with --out, stdout must be empty, got %q", stdout.String())
	}
	if info, err := os.Stat(out); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("the --out file must be readable by its owner only, got %v (%v)", info.Mode().Perm(), err)
	}
}

func TestUsageErrorsExitWithStatus2(t *testing.T) {
	for _, args := range [][]string{{}, {"windows"}, {"linux", "extra"}, {"linux", "--nope"}} {
		var stderr bytes.Buffer
		cmd := exec.Command(binary, args...)
		cmd.Stderr = &stderr
		var exit *exec.ExitError
		if err := cmd.Run(); !errors.As(err, &exit) || exit.ExitCode() != 2 {
			t.Errorf("%v: want exit status 2, got %v", args, err)
		}
		if !strings.Contains(stderr.String(), "usage: agentguard-collector linux") {
			t.Errorf("%v: stderr = %q", args, stderr.String())
		}
	}
}
