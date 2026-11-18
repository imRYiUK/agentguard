package main_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/imRYiUK/agentguard/collector/aws"
	"github.com/imRYiUK/agentguard/collector/awstest"
	"github.com/imRYiUK/agentguard/collector/host"
	"github.com/imRYiUK/agentguard/collector/hosttest"
	"github.com/imRYiUK/agentguard/collector/linux"
)

// TestCollectThenAnalyze runs the whole pipeline over fake Environments: the
// Linux Collector reads a fake host, the AWS Collector reads a fake account,
// and the real CLI analyzes the Snapshots they wrote, together with the
// fixture's agent configuration. It must find the Reach Path through the
// credential file the Linux Collector recorded to the Identity the AWS
// Collector resolved from the same access key, and no secret may reach
// either Snapshot.
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

	// The AWS Collector reads a fake account whose role the credentials
	// resolve to, with the same access key ID as the credential file.
	awsSnap, err := aws.Collect(context.Background(), awstest.New(awstest.Account{
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretKey,
		Caller:          aws.CallerIdentity{Account: "123456789012", ARN: "arn:aws:sts::123456789012:assumed-role/ops/e2e"},
		Roles: map[string]awstest.Principal{"ops": {
			ARN: "arn:aws:iam::123456789012:role/ops",
			Inline: map[string]json.RawMessage{
				"ops-access": json.RawMessage(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`),
			},
		}},
	}), aws.Options{
		Version:    "0.0.0-test",
		Now:        time.Date(2026, 11, 17, 10, 5, 0, 0, time.UTC),
		SnapshotID: "snap-aws-e2e",
	})
	if err != nil {
		t.Fatal(err)
	}
	awsSnapshot, err := aws.MarshalJSON(awsSnap)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{secretKey, accessKeyID} {
		if bytes.Contains(awsSnapshot, []byte(secret)) {
			t.Fatalf("the AWS Snapshot contains a secret value:\n%s", awsSnapshot)
		}
	}

	// The analysis input is the fixture with the Collectors' Snapshots in
	// place of the hand-written ones.
	dir := t.TempDir()
	if err := os.CopyFS(dir, os.DirFS(fixture)); err != nil {
		t.Fatal(err)
	}
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
	edit("agentguard.yaml", func(s string) string {
		return strings.Replace(s, "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8", hostKeyFingerprint, 1)
	})
	if err := os.WriteFile(filepath.Join(dir, "snapshots/linux.json"), snapshot, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "snapshots/aws.json"), awsSnapshot, 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	cmd := exec.Command(binary, "analyze", "--format", "json", "--now", fixtureNow, dir)
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
