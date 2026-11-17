package analysis_test

import (
	"io/fs"
	"os"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/imRYiUK/agentguard/core/analysis"
)

// The valid fixture the cases below start from. Its manifest is
//
//	 1 version: 1
//	 2 agent:
//	 3   name: deploy-agent
//	 4   configs:
//	 5     claudeCodeSettings:
//	 6       - .claude/settings.json
//	 7     mcp:
//	 8       - .mcp.json
//	 9 environments:
//	10   - name: build-host
//	11     type: linux
//	12     identity:
//	13       machineId: e8c913f01b6f9ef3d7f19c3cef1cc390
//	14       sshHostKeyFingerprint: SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8
//	15     snapshot: snapshots/linux.json
//	16   - name: prod-aws
//	17     type: aws
//	18     identity:
//	19       accountId: "123456789012"
//	20     snapshot: snapshots/aws.json
const fixture = "../../cli/testdata/fixtures/credential-file-group-readable/input"

// fixtureFiles returns the fixture's files, with its manifest changed by
// replacing old with new. old must occur in the manifest.
func fixtureFiles(t *testing.T, old, new string) fstest.MapFS {
	t.Helper()
	files := fstest.MapFS{}
	err := fs.WalkDir(os.DirFS(fixture), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		content, err := fs.ReadFile(os.DirFS(fixture), path)
		files[path] = &fstest.MapFile{Data: content}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	manifest := string(files[analysis.ManifestFile].Data)
	if !strings.Contains(manifest, old) {
		t.Fatalf("the fixture manifest has no %q to replace", old)
	}
	files[analysis.ManifestFile] = &fstest.MapFile{Data: []byte(strings.Replace(manifest, old, new, 1))}
	return files
}

func TestAnalyzeAcceptsManifestWithOptionalSections(t *testing.T) {
	files := fixtureFiles(t, "environments:", `declaredBindings:
  - environment: build-host
    identity: deploy
  - environment: prod-aws
    identity: arn:aws:iam::123456789012:role/ops
resourceSensitivity:
  - resource: "arn:aws:s3:::prod-*"
    sensitivity: critical
  - resource: "*"
    sensitivity: low
environments:`)
	result, err := analysis.Analyze(analysis.Input{Files: files})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.ReachPaths) == 0 {
		t.Fatal("want Reach Paths, got none")
	}
	for _, p := range result.ReachPaths {
		if p.AgentDeployment != "deploy-agent" {
			t.Errorf("want Reach Paths of deploy-agent, got %v", p)
		}
	}
}

func TestAnalyzeRejectsMalformedManifest(t *testing.T) {
	tests := []struct {
		name     string
		old, new string
		want     string // the error must contain this
	}{
		{"unknown top-level field", "agent:", "agnet:", "agentguard.yaml:2: agnet: unknown field"},
		{"missing version", "version: 1\n", "", "version: required field is missing"},
		{"unsupported version", "version: 1", "version: 2", "agentguard.yaml:1: version: unsupported version 2"},
		{"version is not a number", "version: 1", `version: "1"`, "agentguard.yaml:1: version: must be the integer 1"},
		{"missing agent name", "  name: deploy-agent\n", "", "agent.name: required field is missing"},
		{"agent name with spaces", "name: deploy-agent", "name: deploy agent", `agentguard.yaml:3: agent.name: must be 1-128 letters`},
		{"unknown config key", "    mcp:", "    mpc:", "agentguard.yaml:7: agent.configs.mpc: unknown field"},
		{"config is not a list", "      - .mcp.json", "      .mcp.json: x", "agent.configs.mcp: must be a list"},
		{"config path escapes the folder", "- .mcp.json", "- ../.mcp.json", `agentguard.yaml:8: agent.configs.mcp[0]: must be a slash-separated path inside the manifest's folder`},
		{"config path is absolute", "- .mcp.json", "- /etc/mcp.json", "agent.configs.mcp[0]: must be a slash-separated path"},
		{"unknown environment type", "type: aws", "type: gcp", `agentguard.yaml:17: environments[1].type: must be one of linux, aws, got "gcp"`},
		{"duplicate environment name", "name: prod-aws", "name: build-host", `agentguard.yaml:16: environments[1].name: duplicate Environment name "build-host" (also environments[0])`},
		{"missing snapshot", "    snapshot: snapshots/aws.json\n", "", "environments[1].snapshot: required field is missing"},
		{"snapshot path escapes the folder", "snapshot: snapshots/aws.json", "snapshot: ../aws.json", "environments[1].snapshot: must be a slash-separated path"},
		{"account ID too short", `"123456789012"`, `"12345"`, `agentguard.yaml:19: environments[1].identity.accountId: must be a 12-digit AWS account ID, got "12345"`},
		{"account ID is a list", `"123456789012"`, `[1]`, "agentguard.yaml:19: environments[1].identity.accountId: must be a 12-digit AWS account ID"},
		{"account ID on a linux Environment", "      machineId:", "      accountId: \"123456789012\"\n      machineId:", "environments[0].identity.accountId: unknown field"},
		{"bad machine ID", "e8c913f01b6f9ef3d7f19c3cef1cc390", "E8C913", `agentguard.yaml:13: environments[0].identity.machineId: must be the 32 lowercase hex characters`},
		{"bad host key fingerprint", "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8", "MD5:aa:bb", "agentguard.yaml:14: environments[0].identity.sshHostKeyFingerprint"},
		{"Linux identity empty", "    identity:\n      machineId: e8c913f01b6f9ef3d7f19c3cef1cc390\n      sshHostKeyFingerprint: SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8\n", "    identity: {}\n", "environments[0].identity: a linux Environment needs machineId or sshHostKeyFingerprint"},
		{"binding names an unknown Environment", "environments:", "declaredBindings:\n  - environment: laptop\n    identity: deploy\nenvironments:", `declaredBindings[0].environment: no Environment named "laptop"`},
		{"binding without identity", "environments:", "declaredBindings:\n  - environment: build-host\nenvironments:", "declaredBindings[0].identity: required field is missing"},
		{"unknown sensitivity level", "environments:", "resourceSensitivity:\n  - resource: \"*\"\n    sensitivity: severe\nenvironments:", `resourceSensitivity[0].sensitivity: must be one of low, medium, high, critical, got "severe"`},
		{"invalid YAML", "environments:", "environments: [", "agentguard.yaml: invalid YAML"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := analysis.Analyze(analysis.Input{Files: fixtureFiles(t, tc.old, tc.new)})
			if err == nil {
				t.Fatalf("want an error containing %q, got none", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

func TestAnalyzeRejectsEmptyManifest(t *testing.T) {
	for _, content := range []string{"", "# only a comment\n"} {
		files := fstest.MapFS{analysis.ManifestFile: {Data: []byte(content)}}
		_, err := analysis.Analyze(analysis.Input{Files: files})
		if err == nil || !strings.Contains(err.Error(), "agentguard.yaml: the manifest is empty") {
			t.Errorf("manifest %q: want an empty-manifest error, got %v", content, err)
		}
	}
}

func TestAnalyzeRejectsMissingFiles(t *testing.T) {
	t.Run("manifest", func(t *testing.T) {
		_, err := analysis.Analyze(analysis.Input{Files: fstest.MapFS{}})
		if err == nil || !strings.Contains(err.Error(), "Agent Manifest") {
			t.Errorf("want an error about the Agent Manifest, got %v", err)
		}
	})
	t.Run("Snapshot named by the manifest", func(t *testing.T) {
		files := fixtureFiles(t, "snapshots/aws.json", "snapshots/other.json")
		_, err := analysis.Analyze(analysis.Input{Files: files})
		if err == nil || !strings.Contains(err.Error(), "environments[1].snapshot") || !strings.Contains(err.Error(), "snapshots/other.json") {
			t.Errorf("want an error naming environments[1].snapshot and the path, got %v", err)
		}
	})
	t.Run("config named by the manifest", func(t *testing.T) {
		files := fixtureFiles(t, "- .mcp.json", "- missing.json")
		_, err := analysis.Analyze(analysis.Input{Files: files})
		if err == nil || !strings.Contains(err.Error(), "agent.configs.mcp") || !strings.Contains(err.Error(), "missing.json") {
			t.Errorf("want an error naming agent.configs.mcp and the path, got %v", err)
		}
	})
}

func TestAnalyzeRejectsEnvironmentIdentityMismatch(t *testing.T) {
	tests := []struct {
		name     string
		old, new string
		want     string
	}{
		{"Linux machine ID",
			"e8c913f01b6f9ef3d7f19c3cef1cc390", "00000000000000000000000000000000",
			`snapshots/linux.json: Environment identity mismatch: Environment "build-host" (environments[0]) expects machineId "00000000000000000000000000000000", but the Snapshot records machineId "e8c913f01b6f9ef3d7f19c3cef1cc390"`},
		{"SSH host key fingerprint",
			"SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8", "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			`snapshots/linux.json: Environment identity mismatch: Environment "build-host" (environments[0]) expects sshHostKeyFingerprint "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"`},
		{"AWS account ID",
			`"123456789012"`, `"999999999999"`,
			`snapshots/aws.json: Environment identity mismatch: Environment "prod-aws" (environments[1]) expects accountId "999999999999", but the Snapshot records accountId "123456789012"`},
		{"Snapshot of the wrong type",
			"snapshot: snapshots/linux.json", "snapshot: snapshots/aws.json",
			`snapshots/aws.json: Environment identity mismatch: Environment "build-host" (environments[0]) is a linux Environment, but the Snapshot is not a linux Snapshot`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := analysis.Analyze(analysis.Input{Files: fixtureFiles(t, tc.old, tc.new)})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("want an error containing\n%s\ngot %v", tc.want, err)
			}
		})
	}
}

func TestAnalyzeOnlyReadsSnapshotsTheManifestNames(t *testing.T) {
	files := fixtureFiles(t, "version: 1", "version: 1")
	files["snapshots/stray.json"] = &fstest.MapFile{Data: []byte("not a Snapshot")}
	if _, err := analysis.Analyze(analysis.Input{Files: files}); err != nil {
		t.Errorf("a Snapshot file the manifest does not name must be ignored: %v", err)
	}
}

func TestAnalyzeReadsUnquotedDigitIdentitiesAsWritten(t *testing.T) {
	files := fixtureFiles(t, `"123456789012"`, `123456789012`)
	if _, err := analysis.Analyze(analysis.Input{Files: files}); err != nil {
		t.Errorf("an unquoted account ID is the same text and must be accepted: %v", err)
	}
	// A machine ID of only digits is also a YAML number. The mismatch
	// message shows it was read as written, not converted.
	files = fixtureFiles(t, "e8c913f01b6f9ef3d7f19c3cef1cc390", "00000000000000000000000000000000")
	_, err := analysis.Analyze(analysis.Input{Files: files})
	if err == nil || !strings.Contains(err.Error(), `expects machineId "00000000000000000000000000000000"`) {
		t.Errorf("want a mismatch naming the machine ID as written, got %v", err)
	}
}
