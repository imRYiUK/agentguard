package main_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/imRYiUK/agentguard/collector/host"
	"github.com/imRYiUK/agentguard/collector/hosttest"
	"github.com/imRYiUK/agentguard/collector/linux"
)

// TestCollectThenAnalyze runs the whole pipeline over a fake Environment: the
// Linux Collector reads a fake host, and the real CLI analyzes the Snapshot it
// wrote, together with the fixture's agent configuration and AWS Snapshot.
// It must find the Reach Path through the credential file the Collector
// recorded, and no secret may reach the Snapshot.
func TestCollectThenAnalyze(t *testing.T) {
	const (
		accessKeyID = "AKIAJ3EXAMPLEKEYEXAM"
		secretKey   = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
		// A throwaway SSH host key and its SHA256 fingerprint, as
		// ssh-keygen -l prints it.
		hostKey            = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKCz9N+BaBs+qZOYOZUHeHq0ZXMM8zxkCTiUS9nc56eq host"
		hostKeyFingerprint = "SHA256:5JlXq0rbIa+l50PPIotxrfxxiZTqQrQRrHry3vahInI"
	)
	fixture := filepath.Join(fixturesDir, "mcp-shell-to-s3-destroy-data", "input")

	fake := &hosttest.Host{
		Proc: host.Process{UID: 1001, GID: 1001},
		Entries: map[string]hosttest.Entry{
			"/etc/machine-id":                   {Lines: []string{"e8c913f01b6f9ef3d7f19c3cef1cc390"}},
			"/etc/ssh/ssh_host_ed25519_key.pub": {Lines: []string{hostKey}},
			"/etc/passwd":                       {Lines: []string{"root:x:0:0::/root:/bin/bash", "deploy:x:1001:1001::/home/deploy:/bin/bash"}},
			"/etc/group":                        {Lines: []string{"root:x:0:", "deploy:x:1001:"}},
			"/home/deploy":                      {Type: "dir", Mode: "0750", UID: 1001, GID: 1001},
			"/home/deploy/.aws":                 {Type: "dir", Mode: "0700", UID: 1001, GID: 1001},
			"/home/deploy/.aws/credentials": {Mode: "0600", UID: 1001, GID: 1001, Lines: []string{
				"[ops]", "aws_access_key_id = " + accessKeyID, "aws_secret_access_key = " + secretKey,
			}},
			"/root": {Type: "dir", Mode: "0700"},
		},
	}
	snap, err := linux.Collect(fake, linux.Options{
		Version:    "0.0.0-test",
		Now:        time.Date(2026, 11, 17, 10, 0, 0, 0, time.UTC),
		SnapshotID: "snap-linux-e2e",
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := linux.MarshalJSON(snap)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{secretKey, accessKeyID} {
		if bytes.Contains(snapshot, []byte(secret)) {
			t.Fatalf("the Snapshot contains a secret value:\n%s", snapshot)
		}
	}

	// The analysis input is the fixture with the Collector's Snapshot in place
	// of the hand-written Linux one. The fixture's AWS Snapshot resolves the
	// access key by its fingerprint, so it is pointed at this key's.
	dir := t.TempDir()
	if err := os.CopyFS(dir, os.DirFS(fixture)); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(accessKeyID))
	edit := func(name string, f func(string) string) {
		t.Helper()
		path := filepath.Join(dir, name)
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(f(string(content))), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	oldLinux, err := os.ReadFile(filepath.Join(dir, "snapshots/linux.json"))
	if err != nil {
		t.Fatal(err)
	}
	oldFingerprint := regexp.MustCompile(`"accessKeyIdFingerprint": "(sha256:[0-9a-f]{64})"`).FindSubmatch(oldLinux)[1]
	edit("snapshots/aws.json", func(s string) string {
		return strings.Replace(s, string(oldFingerprint), "sha256:"+hex.EncodeToString(sum[:]), 1)
	})
	edit("agentguard.yaml", func(s string) string {
		return strings.Replace(s, "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8", hostKeyFingerprint, 1)
	})
	if err := os.WriteFile(filepath.Join(dir, "snapshots/linux.json"), snapshot, 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	cmd := exec.Command(binary, "analyze", "--now", fixtureNow, dir)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("agentguard analyze: %v\nstderr:\n%s", err, stderr.String())
	}
	var result struct {
		ReachPaths []struct {
			Links []struct {
				Kind  string `json:"kind"`
				Label string `json:"label"`
			} `json:"links"`
		} `json:"reachPaths"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.ReachPaths) == 0 {
		t.Fatalf("want a Reach Path through the collected credential file, got none:\n%s", stdout.String())
	}
	found := false
	for _, l := range result.ReachPaths[0].Links {
		if l.Kind == "LINK_KIND_IDENTITY_HOP" && l.Label == "can read AWS credential file /home/deploy/.aws/credentials (profile ops)" {
			found = true
		}
	}
	if !found {
		t.Errorf("the Reach Path does not go through the collected credential file:\n%s", stdout.String())
	}
	for _, secret := range []string{secretKey, accessKeyID} {
		if strings.Contains(stdout.String(), secret) {
			t.Errorf("the analysis result contains a secret value")
		}
	}
}
