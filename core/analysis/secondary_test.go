package analysis_test

import (
	"fmt"
	"strings"
	"testing"
	"testing/fstest"

	analysisv1 "github.com/imRYiUK/agentguard/proto/gen/go/agentguard/analysis/v1"

	"github.com/imRYiUK/agentguard/core/analysis"
)

// secondary lists the secondary findings of an analysis as
// "KIND: label @ source location".
func secondary(t *testing.T, files fstest.MapFS) []string {
	t.Helper()
	result, err := analysis.Analyze(analysis.Input{Files: files})
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, f := range result.SecondaryFindings {
		kind := strings.TrimPrefix(f.Kind.String(), "SECONDARY_FINDING_KIND_")
		out = append(out, fmt.Sprintf("%s: %s @ %s %s", kind, f.Label, f.Evidence.Source, f.Evidence.Location))
	}
	return out
}

func assertFindings(t *testing.T, got []string, want ...string) {
	t.Helper()
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("secondary findings differ\n got:\n  %s\nwant:\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}

const (
	shellFinding = "UNRESTRICTED_COMMAND_EXECUTION: unrestricted command execution: shell Tool (MCP server shell) @ .mcp.json $.mcpServers.shell"
	roleLabel    = "AWS role arn:aws:iam::123456789012:role/ops"
	statement0   = "snapshots/aws.json $.aws.identities[0].policies[0].document.Statement[0]"
)

func TestUnrestrictedShellToolIsASecondaryFinding(t *testing.T) {
	// The fixture's policy also has s3:* on *, which is a wildcard policy.
	assertFindings(t, secondary(t, withPolicy(t, `[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]`)), shellFinding)
}

func TestSecondaryFindingsDoNotNeedAReachPath(t *testing.T) {
	// Nothing grants the agent user the AWS credentials, so there is no
	// Reach Path, yet the shell Tool and the wildcard policy are reported.
	files := fixtureFiles(t, "version: 1", "version: 1")
	files["snapshots/linux.json"] = &fstest.MapFile{Data: []byte(strings.ReplaceAll(
		string(files["snapshots/linux.json"].Data), `"mode": "0640"`, `"mode": "0600"`))}
	if !strings.Contains(string(files["snapshots/linux.json"].Data), `"mode": "0600"`) {
		t.Fatal("the fixture must have a group-readable credential file to change")
	}
	result, err := analysis.Analyze(analysis.Input{Files: files})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.ReachPaths) != 0 {
		t.Fatalf("want no Reach Path, got %d", len(result.ReachPaths))
	}
	assertFindings(t, secondary(t, files),
		shellFinding,
		"WILDCARD_POLICY: wildcard policy: Allow s3:* on * ("+roleLabel+") @ "+statement0)
}

func TestADisabledShellToolIsNotAFinding(t *testing.T) {
	files := withPolicy(t, `[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]`)
	files[".claude/settings.json"] = &fstest.MapFile{Data: []byte(`{"disabledMcpjsonServers":["shell"]}`)}
	assertFindings(t, secondary(t, files))
}

func TestBroadFilesystemToolIsASecondaryFinding(t *testing.T) {
	files := withPolicy(t, `[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]`)
	files[".mcp.json"] = &fstest.MapFile{Data: []byte(`{"mcpServers":{
		"files":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/srv/app","/"]}}}`)}
	assertFindings(t, secondary(t, files),
		"BROAD_FILESYSTEM_ACCESS: broad filesystem access: MCP server files is given / @ .mcp.json $.mcpServers.files.args[3]")
}

func TestWildcardPolicies(t *testing.T) {
	tests := []struct {
		name, statement string
		want            string // the label of the finding, or "" for none
	}{
		{"every action on every resource",
			`{"Effect":"Allow","Action":"*","Resource":"*"}`,
			"Allow * on *"},
		{"every action on some resources",
			`{"Effect":"Allow","Action":"*","Resource":"arn:aws:s3:::prod-*"}`,
			"Allow * on arn:aws:s3:::prod-*"},
		{"every action of a service on every resource",
			`{"Effect":"Allow","Action":["s3:GetObject","iam:*"],"Resource":"*"}`,
			"Allow s3:GetObject, iam:* on *"},
		{"every action of a service on one bucket",
			`{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:::reports"}`, ""},
		{"named actions on every resource",
			`{"Effect":"Allow","Action":["s3:GetObject","s3:List*"],"Resource":"*"}`, ""},
		{"a Deny of everything",
			`{"Effect":"Deny","Action":"*","Resource":"*"}`, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := secondary(t, withPolicy(t, "["+tc.statement+"]"))
			want := []string{shellFinding}
			if tc.want != "" {
				want = append(want, "WILDCARD_POLICY: wildcard policy: "+tc.want+" ("+roleLabel+") @ "+statement0)
			}
			assertFindings(t, got, want...)
		})
	}
}

func TestAConditionalWildcardPolicyHasReducedConfidence(t *testing.T) {
	files := withPolicy(t, `[{"Effect":"Allow","Action":"*","Resource":"*","Condition":{"Bool":{"aws:SecureTransport":"true"}}}]`)
	result, err := analysis.Analyze(analysis.Input{Files: files})
	if err != nil {
		t.Fatal(err)
	}
	f := result.SecondaryFindings[len(result.SecondaryFindings)-1]
	if f.Kind != analysisv1.SecondaryFindingKind_SECONDARY_FINDING_KIND_WILDCARD_POLICY ||
		f.Confidence != analysisv1.Confidence_CONFIDENCE_REDUCED || f.ConfidenceReason == "" {
		t.Errorf("want a wildcard policy finding of reduced confidence with a reason, got %v", f)
	}
}

func TestSecondaryFindingsNameTheAgentDeployment(t *testing.T) {
	result, err := analysis.Analyze(analysis.Input{Files: fixtureFiles(t, "version: 1", "version: 1")})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.SecondaryFindings) == 0 {
		t.Fatal("want secondary findings")
	}
	for _, f := range result.SecondaryFindings {
		if f.AgentDeployment != "deploy-agent" {
			t.Errorf("agent deployment = %q, want deploy-agent", f.AgentDeployment)
		}
		if f.Confidence == analysisv1.Confidence_CONFIDENCE_UNSPECIFIED {
			t.Errorf("finding has no confidence: %v", f)
		}
	}
}
