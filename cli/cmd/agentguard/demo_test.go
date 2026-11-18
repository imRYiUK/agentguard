package main_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The demo Agent Deployments under demo/ are what a reviewer runs without an
// AWS account. They are the same Agent Deployment in two variants: the
// vulnerable one gives its agent a shell Tool and an AWS role that can
// destroy data, the secure one scopes that role to read-only access on one
// bucket. These tests run the real CLI over each folder, exactly as the demo
// README tells a reviewer to.

const demoDir = "../../../demo"

// demoNow is a time shortly after the demo Snapshots were collected, so they
// are not Stale Snapshots. The demo README tells a reviewer to pass the same
// --now, since the demo Snapshots are fixed files that age.
const demoNow = "2026-11-17T12:00:00Z"

func demoInput(variant string) string {
	return filepath.Join(demoDir, variant)
}

func TestVulnerableDemoYieldsTheDestroyDataReachPath(t *testing.T) {
	stdout, stderr, code := runCLI(t, "analyze", "--now", demoNow, demoInput("vulnerable"))
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if !strings.Contains(stdout, "Impact: Destroy Data") {
		t.Errorf("the vulnerable demo must report a Destroy Data Reach Path, got:\n%s", stdout)
	}
	for _, link := range []string{
		"shell Tool (MCP server shell)",
		"Linux user deploy",
		"AWS role arn:aws:iam::123456789012:role/ops",
		"Allow s3:* on *",
	} {
		if !strings.Contains(stdout, link) {
			t.Errorf("the Destroy Data Reach Path must pass through %q, got:\n%s", link, stdout)
		}
	}
}

func TestSecureDemoYieldsNoDestroyDataReachPath(t *testing.T) {
	stdout, stderr, code := runCLI(t, "analyze", "--now", demoNow, demoInput("secure"))
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if strings.Contains(stdout, "Destroy Data") {
		t.Errorf("the secure demo must not report a Destroy Data Reach Path, got:\n%s", stdout)
	}
}

func TestDemoDeploymentGateTellsTheVariantsApart(t *testing.T) {
	_, stderr, code := runCLI(t, "analyze", "--now", demoNow, "--fail-on", "high", demoInput("vulnerable"))
	if code != 3 {
		t.Errorf("vulnerable demo with --fail-on high: want exit status 3, got %d (stderr: %s)", code, stderr)
	}
	_, stderr, code = runCLI(t, "analyze", "--now", demoNow, "--fail-on", "high", demoInput("secure"))
	if code != 0 {
		t.Errorf("secure demo with --fail-on high: want exit status 0, got %d (stderr: %s)", code, stderr)
	}
}

// The two variants are one Agent Deployment: the agent, its Tool, the host,
// and the Environments are the same, and only the AWS role's policy differs.
// If they drift apart the demo stops being a fair comparison.
func TestDemoVariantsAreTheSameAgentDeploymentExceptForThePolicy(t *testing.T) {
	for _, file := range []string{
		"agentguard.yaml",
		".mcp.json",
		".claude/settings.json",
		"snapshots/linux.json",
	} {
		vulnerable := readDemoFile(t, filepath.Join(demoInput("vulnerable"), file))
		secure := readDemoFile(t, filepath.Join(demoInput("secure"), file))
		if vulnerable != secure {
			t.Errorf("%s differs between the demo variants; only snapshots/aws.json may differ", file)
		}
	}
	// ...and the policy is the one thing that does differ, so a copy of one
	// variant's Snapshot over the other's cannot pass as a comparison.
	if readDemoFile(t, filepath.Join(demoInput("vulnerable"), "snapshots/aws.json")) ==
		readDemoFile(t, filepath.Join(demoInput("secure"), "snapshots/aws.json")) {
		t.Error("snapshots/aws.json is the same in both demo variants; the secure one must scope the role's policy")
	}
}

func readDemoFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
