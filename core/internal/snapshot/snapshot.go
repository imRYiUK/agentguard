// Package snapshot reads a Snapshot file, which is untrusted input. Parse
// decodes the Protobuf canonical JSON, validates it against the schema, and
// rejects a Snapshot that looks like it holds a secret value.
package snapshot

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/imRYiUK/agentguard/core/internal/limits"
	snapshotv1 "github.com/imRYiUK/agentguard/proto/gen/go/agentguard/snapshot/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// SchemaVersion is the Snapshot schema version this package reads.
const SchemaVersion = "1"

// Parse reads and validates a Snapshot. source is the name used in error
// messages. An error does not echo a value that looks like a secret: such a
// Snapshot is rejected by location and kind only. Other text from the
// Snapshot, such as an unknown field name, can appear in an error.
func Parse(source string, content []byte) (*snapshotv1.Snapshot, error) {
	if err := limits.CheckJSON(content, limits.MaxSnapshotBytes); err != nil {
		return nil, fmt.Errorf("%s: invalid Snapshot: %w", source, err)
	}
	// protojson quotes the text it fails on, which could be a secret, so the
	// syntax is checked first with encoding/json, whose errors name only the
	// offending character and its offset.
	var doc any
	if err := json.Unmarshal(content, &doc); err != nil {
		return nil, fmt.Errorf("%s: invalid Snapshot: not valid JSON: %w", source, err)
	}
	if err := rejectSecrets(source, doc); err != nil {
		return nil, err
	}
	var snap snapshotv1.Snapshot
	if err := protojson.Unmarshal(content, &snap); err != nil {
		// protojson deliberately varies the whitespace of its messages
		// between builds, so it is normalized to keep errors byte-stable.
		msg := strings.ReplaceAll(err.Error(), "\u00a0", " ")
		return nil, fmt.Errorf("%s: invalid Snapshot: %s", source, msg)
	}
	if err := validate(&snap); err != nil {
		return nil, fmt.Errorf("%s: invalid Snapshot: %w", source, err)
	}
	return &snap, nil
}

var (
	machineID   = regexp.MustCompile(`^[0-9a-f]{32}$`)
	hostKeyFP   = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)
	awsAccount  = regexp.MustCompile(`^[0-9]{12}$`)
	fingerprint = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	arn         = regexp.MustCompile(`^arn:aws[a-z-]*:[a-z0-9-]+:[a-z0-9-]*:[0-9]*:.+$`)
	// An AWS managed policy has "aws" where an account ID would be.
	policyARN = regexp.MustCompile(`^arn:aws[a-z-]*:iam::([0-9]{12}|aws):policy/.+$`)
)

const fingerprintWant = `must be a fingerprint: "sha256:" and 64 hex characters`

// problem is a schema violation at a JSONPath.
type problem struct {
	path, message string
}

func (p *problem) Error() string { return p.path + ": " + p.message }

func missing(path string) error { return &problem{path, "required field is missing"} }

func invalid(path, format string, args ...any) error {
	return &problem{path, fmt.Sprintf(format, args...)}
}

// validate checks the rules the Protobuf schema cannot express: required
// fields, formats, and that the parts of a Snapshot agree with each other.
func validate(s *snapshotv1.Snapshot) error {
	switch {
	case s.GetSchemaVersion() == "":
		return missing("$.schemaVersion")
	case s.GetSchemaVersion() != SchemaVersion:
		return invalid("$.schemaVersion", "unsupported version %q (this AgentGuard reads version %q)", s.GetSchemaVersion(), SchemaVersion)
	case s.GetSnapshotId() == "":
		return missing("$.snapshotId")
	case s.GetCollectorVersion() == "":
		return missing("$.collectorVersion")
	case s.GetCollectedAt() == nil:
		return missing("$.collectedAt")
	case s.GetCollectedBy() == "":
		return missing("$.collectedBy")
	}
	if err := validateBlindSpots(s); err != nil {
		return err
	}

	env := s.GetEnvironment()
	if env == nil || env.GetIdentity() == nil {
		return missing("$.environment")
	}
	switch id := env.GetIdentity().(type) {
	case *snapshotv1.EnvironmentIdentity_Linux:
		if err := validateLinuxIdentity(id.Linux); err != nil {
			return err
		}
		p, ok := s.GetPayload().(*snapshotv1.Snapshot_Linux)
		if !ok {
			if s.GetPayload() == nil {
				return missing("$.linux")
			}
			return invalid("$.environment", "a linux identity does not match the aws payload")
		}
		return validateLinux(p.Linux)
	case *snapshotv1.EnvironmentIdentity_Aws:
		if !awsAccount.MatchString(id.Aws.GetAccountId()) {
			return invalid("$.environment.aws.accountId", "must be a 12-digit AWS account ID")
		}
		p, ok := s.GetPayload().(*snapshotv1.Snapshot_Aws)
		if !ok {
			if s.GetPayload() == nil {
				return missing("$.aws")
			}
			return invalid("$.environment", "an aws identity does not match the linux payload")
		}
		return validateAWS(p.Aws)
	}
	return missing("$.environment")
}

func validateBlindSpots(s *snapshotv1.Snapshot) error {
	for i, b := range s.GetBlindSpots() {
		path := fmt.Sprintf("$.blindSpots[%d]", i)
		if b.GetAttempted() == "" {
			return missing(path + ".attempted")
		}
		if b.GetReason() == "" {
			return missing(path + ".reason")
		}
	}
	return nil
}

func validateLinuxIdentity(id *snapshotv1.LinuxEnvironmentIdentity) error {
	const path = "$.environment.linux"
	if id.GetMachineId() == "" && id.GetSshHostKeyFingerprint() == "" {
		return invalid(path, "needs machineId or sshHostKeyFingerprint")
	}
	if id.GetMachineId() != "" && !machineID.MatchString(id.GetMachineId()) {
		return invalid(path+".machineId", "must be the 32 lowercase hex characters of /etc/machine-id")
	}
	if id.GetSshHostKeyFingerprint() != "" && !hostKeyFP.MatchString(id.GetSshHostKeyFingerprint()) {
		return invalid(path+".sshHostKeyFingerprint", `must be an SSH host key fingerprint such as "SHA256:..."`)
	}
	return nil
}

func validateLinux(l *snapshotv1.LinuxPayload) error {
	user := l.GetAgentUser()
	if user == nil {
		return missing("$.linux.agentUser")
	}
	if user.GetName() == "" {
		return missing("$.linux.agentUser.name")
	}
	for i, g := range user.GetGroups() {
		if g.GetName() == "" {
			return missing(fmt.Sprintf("$.linux.agentUser.groups[%d].name", i))
		}
	}
	if sock := l.GetDockerSocket(); sock != nil {
		const path = "$.linux.dockerSocket"
		if !strings.HasPrefix(sock.GetPath(), "/") {
			return invalid(path+".path", "must be an absolute path")
		}
		if _, err := strconv.ParseUint(sock.GetMode(), 8, 12); err != nil {
			return invalid(path+".mode", "%q is not an octal permission mode", sock.GetMode())
		}
	}
	for i, f := range l.GetCredentialFiles() {
		path := fmt.Sprintf("$.linux.credentialFiles[%d]", i)
		if !strings.HasPrefix(f.GetPath(), "/") {
			return invalid(path+".path", "must be an absolute path")
		}
		if f.GetKind() == snapshotv1.CredentialKind_CREDENTIAL_KIND_UNSPECIFIED {
			return missing(path + ".kind")
		}
		if _, err := strconv.ParseUint(f.GetMode(), 8, 12); err != nil {
			return invalid(path+".mode", "%q is not an octal permission mode", f.GetMode())
		}
		if !fingerprint.MatchString(f.GetFingerprint()) {
			return invalid(path+".fingerprint", fingerprintWant)
		}
		for j, p := range f.GetAwsProfiles() {
			ppath := fmt.Sprintf("%s.awsProfiles[%d]", path, j)
			if p.GetName() == "" {
				return missing(ppath + ".name")
			}
			if p.GetAccessKeyIdFingerprint() != "" && !fingerprint.MatchString(p.GetAccessKeyIdFingerprint()) {
				return invalid(ppath+".accessKeyIdFingerprint", fingerprintWant)
			}
		}
	}
	return nil
}

func validateAWS(a *snapshotv1.AwsPayload) error {
	for i, id := range a.GetIdentities() {
		path := fmt.Sprintf("$.aws.identities[%d]", i)
		if id.GetArn() == "" {
			return missing(path + ".arn")
		}
		if !arn.MatchString(id.GetArn()) {
			return invalid(path+".arn", "must be an ARN")
		}
		for j, fp := range id.GetAccessKeyIdFingerprints() {
			if !fingerprint.MatchString(fp) {
				return invalid(fmt.Sprintf("%s.accessKeyIdFingerprints[%d]", path, j), fingerprintWant)
			}
		}
		if err := validatePolicies(path+".policies", id.GetPolicies()); err != nil {
			return err
		}
		for j, g := range id.GetGroups() {
			gpath := fmt.Sprintf("%s.groups[%d]", path, j)
			if g.GetArn() == "" {
				return missing(gpath + ".arn")
			}
			if !arn.MatchString(g.GetArn()) {
				return invalid(gpath+".arn", "must be an ARN")
			}
			if g.GetName() == "" {
				return missing(gpath + ".name")
			}
			if err := validatePolicies(gpath+".policies", g.GetPolicies()); err != nil {
				return err
			}
		}
	}
	return nil
}

// validatePolicies checks the identity-based policies attached to an Identity
// or a group. path is the JSONPath of the list.
func validatePolicies(path string, policies []*snapshotv1.AwsPolicy) error {
	for i, p := range policies {
		ppath := fmt.Sprintf("%s[%d]", path, i)
		if p.GetName() == "" {
			return missing(ppath + ".name")
		}
		if p.GetDocument() == nil {
			return missing(ppath + ".document")
		}
		switch p.GetKind() {
		case snapshotv1.PolicyKind_POLICY_KIND_MANAGED:
			if p.GetArn() == "" {
				return missing(ppath + ".arn")
			}
			if !policyARN.MatchString(p.GetArn()) {
				return invalid(ppath+".arn", "must be an IAM policy ARN")
			}
		case snapshotv1.PolicyKind_POLICY_KIND_INLINE:
			if p.GetArn() != "" {
				return invalid(ppath+".arn", "an inline policy has no ARN")
			}
		default:
			return missing(ppath + ".kind")
		}
	}
	return nil
}
