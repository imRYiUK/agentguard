package analysis_test

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/imRYiUK/agentguard/core/analysis"
)

// edit returns a copy of files with old replaced by new in the named file.
// old must occur in the file.
func edit(t *testing.T, files fstest.MapFS, name, old, new string) fstest.MapFS {
	t.Helper()
	out := fstest.MapFS{}
	for k, v := range files {
		out[k] = &fstest.MapFile{Data: v.Data}
	}
	f, ok := out[name]
	if !ok {
		t.Fatalf("the fixture has no file %q", name)
	}
	if !strings.Contains(string(f.Data), old) {
		t.Fatalf("%s has no %q to replace", name, old)
	}
	f.Data = []byte(strings.Replace(string(f.Data), old, new, 1))
	return out
}

// base returns the unmodified valid fixture.
func base(t *testing.T) fstest.MapFS {
	return fixtureFiles(t, "version: 1", "version: 1")
}

func analyzeError(t *testing.T, files fstest.MapFS) string {
	t.Helper()
	_, err := analysis.Analyze(analysis.Input{Files: files})
	if err == nil {
		t.Fatal("want an error, got none")
	}
	return err.Error()
}

func TestAnalyzeRejectsInvalidSnapshots(t *testing.T) {
	const linux, aws = "snapshots/linux.json", "snapshots/aws.json"
	tests := []struct {
		name     string
		file     string
		old, new string
		want     string
	}{
		{"not JSON", linux, `"schemaVersion"`, `schemaVersion`,
			"snapshots/linux.json: invalid Snapshot:"},
		{"unknown field", linux, `"collectedBy"`, `"collectedBI"`,
			"snapshots/linux.json: invalid Snapshot:"},
		{"uid is a string", linux, `"uid": 1001`, `"uid": "root"`,
			"snapshots/linux.json: invalid Snapshot:"},
		{"missing schemaVersion", linux, "  \"schemaVersion\": \"1\",\n", "",
			"snapshots/linux.json: invalid Snapshot: $.schemaVersion: required field is missing"},
		{"unsupported schemaVersion", linux, `"schemaVersion": "1"`, `"schemaVersion": "2"`,
			`$.schemaVersion: unsupported version "2" (this AgentGuard reads version "1")`},
		{"missing snapshotId", linux, "  \"snapshotId\": \"snap-linux-0001\",\n", "",
			"snapshots/linux.json: invalid Snapshot: $.snapshotId: required field is missing"},
		{"missing collectorVersion", linux, "  \"collectorVersion\": \"0.0.0-fixture\",\n", "",
			"$.collectorVersion: required field is missing"},
		{"missing collectedAt", linux, "  \"collectedAt\": \"2026-11-17T10:00:00Z\",\n", "",
			"$.collectedAt: required field is missing"},
		{"missing collectedBy", linux, "  \"collectedBy\": \"deploy\",\n", "",
			"$.collectedBy: required field is missing"},
		{"missing Environment identity", aws, "\"environment\": {\n    \"aws\": {\n      \"accountId\": \"123456789012\"\n    }\n  },", "",
			"$.environment: required field is missing"},
		{"Environment identity disagrees with the payload", aws, `"aws": {
      "accountId": "123456789012"`, `"linux": {
      "machineId": "e8c913f01b6f9ef3d7f19c3cef1cc390"`,
			"$.environment: a linux identity does not match the aws payload"},
		{"machine ID malformed", linux, "e8c913f01b6f9ef3d7f19c3cef1cc390", "E8C9",
			"$.environment.linux.machineId: must be the 32 lowercase hex characters"},
		{"host key fingerprint malformed", linux, "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8", "MD5:aa",
			"$.environment.linux.sshHostKeyFingerprint: must be an SSH host key fingerprint"},
		{"account ID malformed", aws, `"accountId": "123456789012"`, `"accountId": "12345"`,
			"$.environment.aws.accountId: must be a 12-digit AWS account ID"},
		{"blind spot without a reason", linux, `"reason": "permission denied"`, `"reason": ""`,
			"$.blindSpots[0].reason: required field is missing"},
		{"agent user missing", linux, `"agentUser"`, `"agentUserX"`,
			"snapshots/linux.json: invalid Snapshot:"},
		{"agent user without a name", linux, `"name": "deploy",
      "uid"`, `"uid"`,
			"$.linux.agentUser.name: required field is missing"},
		{"credential file path is relative", linux, `"/home/ops/.aws/credentials"`, `"ops/.aws/credentials"`,
			"$.linux.credentialFiles[0].path: must be an absolute path"},
		{"credential file kind unspecified", linux, `"CREDENTIAL_KIND_AWS_SHARED_CREDENTIALS"`, `"CREDENTIAL_KIND_UNSPECIFIED"`,
			"$.linux.credentialFiles[0].kind: required field is missing"},
		{"credential file mode is not octal", linux, `"0640"`, `"rw-r-----"`,
			`$.linux.credentialFiles[0].mode: "rw-r-----" is not an octal permission mode`},
		{"credential file fingerprint malformed", linux, "sha256:541789cf5fa4ea552aac60dfca115120c222ef42791952bb29c1d406efd6748d", "541789",
			"$.linux.credentialFiles[0].fingerprint: must be a fingerprint"},
		{"profile fingerprint malformed", linux, `"accessKeyIdFingerprint": "sha256:2199c040063f5758eba7a989455e6c716f3ac3ad2aa6f73b9b3ae8967d192380"`, `"accessKeyIdFingerprint": "AKIA"`,
			"$.linux.credentialFiles[0].awsProfiles[0].accessKeyIdFingerprint: must be a fingerprint"},
		{"identity ARN missing", aws, `"arn": "arn:aws:iam::123456789012:role/ops"`, `"arn": ""`,
			"$.aws.identities[0].arn: required field is missing"},
		{"identity ARN malformed", aws, `"arn:aws:iam::123456789012:role/ops"`, `"role/ops"`,
			"$.aws.identities[0].arn: must be an ARN"},
		{"identity key fingerprint malformed", aws, "sha256:2199c040063f5758eba7a989455e6c716f3ac3ad2aa6f73b9b3ae8967d192380", "nope",
			"$.aws.identities[0].accessKeyIdFingerprints[0]: must be a fingerprint"},
		{"policy without a name", aws, `"name": "ops-access"`, `"name": ""`,
			"$.aws.identities[0].policies[0].name: required field is missing"},
		{"policy without a document", aws, `"document": {`, `"documentX": {`,
			"snapshots/aws.json: invalid Snapshot:"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := analyzeError(t, edit(t, base(t), tc.file, tc.old, tc.new))
			if !strings.Contains(got, tc.want) {
				t.Errorf("error %q does not contain %q", got, tc.want)
			}
		})
	}
}

func TestAnalyzeRejectsSnapshotWithoutPayload(t *testing.T) {
	files := base(t)
	files["snapshots/linux.json"] = &fstest.MapFile{Data: []byte(`{
  "schemaVersion": "1",
  "snapshotId": "s",
  "collectorVersion": "v",
  "collectedAt": "2026-11-17T10:00:00Z",
  "collectedBy": "deploy",
  "environment": {"linux": {"machineId": "e8c913f01b6f9ef3d7f19c3cef1cc390"}}
}`)}
	got := analyzeError(t, files)
	want := "snapshots/linux.json: invalid Snapshot: $.linux: required field is missing"
	if !strings.Contains(got, want) {
		t.Errorf("error %q does not contain %q", got, want)
	}
}

func TestAnalyzeRejectsSnapshotsThatLookLikeTheyHoldSecrets(t *testing.T) {
	const linux, aws = "snapshots/linux.json", "snapshots/aws.json"
	// Fake values only. The AWS ones are the examples from the AWS documentation.
	const (
		secretKey    = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
		accessKeyID  = "AKIAIOSFODNN7EXAMPLE"
		sessionToken = "IQoJb3JpZ2luX2VjEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE"
		privateKey   = `-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----`
	)
	tests := []struct {
		name     string
		file     string
		old, new string
		want     string // the error must contain this
		secret   string // the error must not contain this
	}{
		{"secret access key under a secret field name", linux,
			`"name": "ops",`, `"name": "ops", "secretAccessKey": "` + secretKey + `",`,
			`snapshots/linux.json: Snapshot rejected: $.linux.credentialFiles[0].awsProfiles[0].secretAccessKey looks like a secret value (the field name says it holds a secret)`, secretKey},
		{"session token under a secret field name", aws,
			`"name": "ops-access",`, `"name": "ops-access", "aws_session_token": "x",`,
			`$.aws.identities[0].policies[0].aws_session_token looks like a secret value`, ""},
		{"secret access key as a bare value", linux,
			`"reason": "permission denied"`, `"reason": "` + secretKey + `"`,
			`$.blindSpots[0].reason looks like an AWS secret access key`, secretKey},
		{"secret access key in credential file text", linux,
			`"reason": "permission denied"`, `"reason": "[ops]\naws_secret_access_key = ` + secretKey + `"`,
			`$.blindSpots[0].reason looks like an AWS secret access key`, secretKey},
		{"access key ID", linux,
			`"reason": "permission denied"`, `"reason": "key ` + accessKeyID + ` rejected"`,
			`$.blindSpots[0].reason looks like an AWS access key ID`, accessKeyID},
		{"session token", linux,
			`"reason": "permission denied"`, `"reason": "` + sessionToken + `"`,
			`$.blindSpots[0].reason looks like an AWS session token`, sessionToken},
		{"private key", linux,
			`"reason": "permission denied"`, `"reason": "` + privateKey + `"`,
			`$.blindSpots[0].reason looks like a private key`, "b3BlbnNzaC1rZXktdjE"},
		{"GitHub token", linux,
			`"reason": "permission denied"`, `"reason": "ghp_abcdefghijklmnopqrstuvwxyz0123456789"`,
			`$.blindSpots[0].reason looks like a GitHub token`, "ghp_abcdefghijklmnopqrstuvwxyz"},
		{"Slack token", linux,
			`"reason": "permission denied"`, `"reason": "xoxb-123456789012-abcdefghijklmnop"`,
			`$.blindSpots[0].reason looks like a Slack token`, "xoxb-1234"},
		{"Anthropic API key", linux,
			`"reason": "permission denied"`, `"reason": "sk-ant-api03-abcdefghijklmnopqrstuvwxyz"`,
			`$.blindSpots[0].reason looks like an API key`, "sk-ant-api03"},
		{"JSON Web Token", linux,
			`"reason": "permission denied"`, `"reason": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N"`,
			`$.blindSpots[0].reason looks like a JSON Web Token`, "eyJhbGci"},
		{"secret field holding a number", linux,
			`"name": "ops",`, `"name": "ops", "token": 123456,`,
			`$.linux.credentialFiles[0].awsProfiles[0].token looks like a secret value`, ""},
		{"secret field holding an object", linux,
			`"name": "ops",`, `"name": "ops", "password": {"value": "x"},`,
			`$.linux.credentialFiles[0].awsProfiles[0].password looks like a secret value`, ""},
		{"secret in a policy document value", aws,
			`"Action": "s3:*",`, `"Action": "s3:*", "Sid": "` + secretKey + `",`,
			`$.aws.identities[0].policies[0].document.Statement[0].Sid looks like an AWS secret access key`, secretKey},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := analyzeError(t, edit(t, base(t), tc.file, tc.old, tc.new))
			if !strings.Contains(got, tc.want) {
				t.Errorf("error %q does not contain %q", got, tc.want)
			}
			if tc.secret != "" && strings.Contains(got, tc.secret) {
				t.Errorf("the error echoes the secret: %q", got)
			}
		})
	}
}

func TestAnalyzeAcceptsFingerprintsAndIdentifiersThatAreNotSecrets(t *testing.T) {
	// The fixture holds sha256 fingerprints, ARNs, a machine ID, and an SSH
	// host key fingerprint. None of them is a secret.
	if _, err := analysis.Analyze(analysis.Input{Files: base(t)}); err != nil {
		t.Fatal(err)
	}
	// Words that name secrets are fine as values; only a field whose name
	// says it holds a secret and has a value is suspicious.
	files := edit(t, base(t), "snapshots/linux.json",
		`"reason": "permission denied"`, `"reason": "secret access key file is not readable; token store missing"`)
	if _, err := analysis.Analyze(analysis.Input{Files: files}); err != nil {
		t.Errorf("prose that mentions secrets must be accepted: %v", err)
	}
}

func nested(depth int) string {
	return strings.Repeat("[", depth) + strings.Repeat("]", depth)
}

func TestAnalyzeEnforcesInputLimits(t *testing.T) {
	const (
		tooDeep  = "nesting is deeper than the limit of 32 levels"
		pad      = "a " // not a secret, and not valid base64
		mib      = 1 << 20
		oversize = "too large (the limit is "
	)
	tests := []struct {
		name  string
		files func(t *testing.T) fstest.MapFS
		want  string
	}{
		{"manifest too large", func(t *testing.T) fstest.MapFS {
			return edit(t, base(t), "agentguard.yaml", "version: 1", "# "+strings.Repeat(pad, mib/2)+"\nversion: 1")
		}, "agentguard.yaml: " + oversize + "1048576 bytes)"},
		{"manifest too deep", func(t *testing.T) fstest.MapFS {
			return edit(t, base(t), "agentguard.yaml", "environments:", "resourceSensitivity: "+nested(40)+"\nenvironments:")
		}, "agentguard.yaml: " + tooDeep},
		{"manifest list too long", func(t *testing.T) fstest.MapFS {
			return edit(t, base(t), "agentguard.yaml", "environments:",
				"declaredBindings:\n"+strings.Repeat("  - {environment: build-host, identity: deploy}\n", 65)+"environments:")
		}, "declaredBindings: too many entries (65; the limit is 64)"},
		{"Claude Code settings too large", func(t *testing.T) fstest.MapFS {
			return edit(t, base(t), ".claude/settings.json", `"permissions"`, `"note": "`+strings.Repeat(pad, mib/2)+`", "permissions"`)
		}, ".claude/settings.json: " + oversize + "1048576 bytes)"},
		{"Claude Code settings too deep", func(t *testing.T) fstest.MapFS {
			return edit(t, base(t), ".claude/settings.json", `"permissions"`, `"deep": `+nested(40)+`, "permissions"`)
		}, ".claude/settings.json: invalid Claude Code settings: " + tooDeep},
		{"MCP configuration too large", func(t *testing.T) fstest.MapFS {
			return edit(t, base(t), ".mcp.json", `"mcpServers"`, `"note": "`+strings.Repeat(pad, mib/2)+`", "mcpServers"`)
		}, ".mcp.json: " + oversize + "1048576 bytes)"},
		{"MCP configuration too deep", func(t *testing.T) fstest.MapFS {
			return edit(t, base(t), ".mcp.json", `"mcpServers"`, `"deep": `+nested(40)+`, "mcpServers"`)
		}, ".mcp.json: invalid MCP configuration: " + tooDeep},
		{"Snapshot too large", func(t *testing.T) fstest.MapFS {
			return edit(t, base(t), "snapshots/linux.json", `"collectedBy"`, `"padding": "`+strings.Repeat(pad, 4*mib+1)+`", "collectedBy"`)
		}, "snapshots/linux.json: " + oversize + "8388608 bytes)"},
		{"Snapshot too deep", func(t *testing.T) fstest.MapFS {
			return edit(t, base(t), "snapshots/linux.json", `"collectedBy"`, `"deep": `+nested(40)+`, "collectedBy"`)
		}, "snapshots/linux.json: invalid Snapshot: " + tooDeep},
		{"IAM policy document too large", func(t *testing.T) fstest.MapFS {
			return edit(t, base(t), "snapshots/aws.json", `"Action": "s3:*",`, `"Action": "s3:*", "Sid": "`+strings.Repeat(pad, 150_000)+`",`)
		}, "snapshots/aws.json: $.aws.identities[0].policies[0].document: IAM policy document is too large (the limit is 262144 bytes)"},
		{"IAM policy document too deep", func(t *testing.T) fstest.MapFS {
			return edit(t, base(t), "snapshots/aws.json", `"Action": "s3:*",`, `"Action": "s3:*", "Condition": {"StringEquals": {"k": `+nested(14)+`}},`)
		}, "snapshots/aws.json: $.aws.identities[0].policies[0].document: IAM policy document is nested deeper than the limit of 16 levels"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := analyzeError(t, tc.files(t))
			if !strings.Contains(got, tc.want) {
				t.Errorf("error %q does not contain %q", got, tc.want)
			}
		})
	}
}

// Error messages are logged, so they must never carry a value from a Snapshot
// that looks like a secret, even when the Snapshot is not valid JSON or has
// a secret where a field name belongs.
func TestAnalyzeErrorsNeverEchoSecrets(t *testing.T) {
	const accessKeyID = "AKIAIOSFODNN7EXAMPLE"
	tests := []struct{ name, content string }{
		{"a bare secret", accessKeyID},
		{"a secret after valid JSON", `{} ` + accessKeyID},
		{"a secret as a field name", `{"` + accessKeyID + `": 1}`},
		{"a secret as an enum value", `{"linux": {"credentialFiles": [{"kind": "` + accessKeyID + `"}]}}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			files := base(t)
			files["snapshots/linux.json"] = &fstest.MapFile{Data: []byte(tc.content)}
			got := analyzeError(t, files)
			if strings.Contains(got, accessKeyID) {
				t.Errorf("the error echoes the secret: %q", got)
			}
		})
	}
}

func TestAnalyzeRejectsMalformedPolicyDocuments(t *testing.T) {
	tests := []struct {
		name     string
		old, new string
		want     string
	}{
		{"Statement is a string", `"Statement": [`, `"Statement": "Allow", "Ignored": [`,
			"document: invalid policy document: Statement must be a statement or a list of statements"},
		{"Action is a number", `"Action": "s3:*"`, `"Action": 7`,
			"document: invalid policy document: Action and Resource must be a string or a list of strings"},
		{"Effect is a list", `"Effect": "Allow",
                  "Action": "s3:*"`, `"Effect": ["Allow"],
                  "Action": "s3:*"`,
			"document: invalid policy document: Effect must not be an array"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := analyzeError(t, edit(t, base(t), "snapshots/aws.json", tc.old, tc.new))
			if !strings.Contains(got, tc.want) {
				t.Errorf("error %q does not contain %q", got, tc.want)
			}
		})
	}
}

// protojson varies the whitespace of its error messages between builds. An
// error that depends on it would make a golden fixture pass or fail with the
// binary, so the messages must be byte-stable.
func TestAnalyzeErrorsFromProtojsonAreByteStable(t *testing.T) {
	got := analyzeError(t, edit(t, base(t), "snapshots/linux.json", `"collectedBy"`, `"collectedBI"`))
	if strings.Contains(got, " ") {
		t.Errorf("the error contains a non-breaking space: %q", got)
	}
}
