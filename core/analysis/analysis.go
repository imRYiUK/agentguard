// Package analysis is AgentGuard's core library. Analyze takes an Analysis
// Input and returns the Reach Paths of the Agent Deployment it describes.
// Parsing, Identity Binding, Identity Hops, policy evaluation, and Impact
// mapping all sit behind it.
package analysis

import (
	"bytes"
	"cmp"
	"encoding/json"
	"fmt"
	"io/fs"
	"slices"
	"strconv"
	"strings"

	analysisv1 "github.com/imRYiUK/agentguard/proto/gen/go/agentguard/analysis/v1"
	snapshotv1 "github.com/imRYiUK/agentguard/proto/gen/go/agentguard/snapshot/v1"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/imRYiUK/agentguard/core/internal/agentconfig"
	"github.com/imRYiUK/agentguard/core/internal/awspolicy"
	"github.com/imRYiUK/agentguard/core/internal/impact"
	"github.com/imRYiUK/agentguard/core/internal/limits"
	"github.com/imRYiUK/agentguard/core/internal/manifest"
	"github.com/imRYiUK/agentguard/core/internal/snapshot"
)

// ManifestFile is the name of the Agent Manifest at the root of an Analysis
// Input's files.
const ManifestFile = "agentguard.yaml"

// Input is an Analysis Input: the Agent Manifest and every file it refers to,
// as a file tree rooted at the manifest's folder. Evidence names each file by
// its slash-separated path in the tree.
type Input struct {
	Files fs.FS
}

// Analyze returns the Reach Paths found in the Analysis Input. The same
// input always gives the same result.
func Analyze(in Input) (*analysisv1.AnalysisResult, error) {
	m, err := readManifest(in.Files)
	if err != nil {
		return nil, err
	}
	impacts, err := impact.Default()
	if err != nil {
		return nil, err
	}
	settings, err := readFiles(in.Files, "agent.configs.claudeCodeSettings", m.Agent.ClaudeCodeSettings)
	if err != nil {
		return nil, err
	}
	mcpConfigs, err := readFiles(in.Files, "agent.configs.mcp", m.Agent.MCP)
	if err != nil {
		return nil, err
	}
	tools, err := agentconfig.ShellTools(configFiles(mcpConfigs), configFiles(settings))
	if err != nil {
		return nil, err
	}
	linux, aws, err := readSnapshots(in.Files, m.Environments)
	if err != nil {
		return nil, err
	}

	result := &analysisv1.AnalysisResult{}
	for _, tool := range tools {
		toolLink := link(analysisv1.LinkKind_LINK_KIND_TOOL,
			fmt.Sprintf("shell Tool (MCP server %s)", tool.Server), tool.Source, tool.Location)
		for _, host := range linux {
			hops, err := credentialHops(host, aws)
			if err != nil {
				return nil, err
			}
			for _, hop := range hops {
				for _, perm := range hop.to.grants {
					for _, mapping := range impacts.Lookup(perm.Action) {
						result.ReachPaths = append(result.ReachPaths, &analysisv1.ReachPath{
							AgentDeployment: m.Agent.Name,
							Links: []*analysisv1.Link{
								toolLink,
								host.userLink,
								hop.link,
								hop.to.link,
								perm.link,
								link(analysisv1.LinkKind_LINK_KIND_IMPACT, mapping.Impact, mapping.Source, mapping.Location),
							},
						})
					}
				}
			}
		}
	}
	return result, nil
}

func readManifest(files fs.FS) (*manifest.Manifest, error) {
	content, err := limits.ReadFile(files, ManifestFile, limits.MaxConfigBytes)
	if err != nil {
		return nil, fmt.Errorf("reading the Agent Manifest: %w", err)
	}
	m, err := manifest.Parse(ManifestFile, content)
	if err != nil {
		return nil, err
	}
	return m, nil
}

// inputFile is one input file and the name it is reported under in evidence.
type inputFile struct {
	Source  string
	Content []byte
}

// readFiles reads the files a manifest list field names. Errors name the
// field and the entry.
func readFiles(files fs.FS, field string, paths []string) ([]inputFile, error) {
	var out []inputFile
	for i, p := range paths {
		content, err := limits.ReadFile(files, p, limits.MaxConfigBytes)
		if err != nil {
			return nil, fmt.Errorf("%s[%d]: %w", field, i, err)
		}
		out = append(out, inputFile{Source: p, Content: content})
	}
	return out, nil
}

// MarshalJSON encodes a result as indented JSON. The encoding is stable, so
// the same result always gives byte-identical output.
func MarshalJSON(result *analysisv1.AnalysisResult) ([]byte, error) {
	// protojson deliberately varies its whitespace between builds, so the
	// output is re-indented to make it byte-stable.
	raw, err := protojson.Marshal(result)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := json.Indent(&out, raw, "", "  "); err != nil {
		return nil, err
	}
	out.WriteByte('\n')
	return out.Bytes(), nil
}

func configFiles(files []inputFile) []agentconfig.File {
	out := make([]agentconfig.File, len(files))
	for i, f := range files {
		out[i] = agentconfig.File{Source: f.Source, Content: f.Content}
	}
	slices.SortFunc(out, func(a, b agentconfig.File) int { return cmp.Compare(a.Source, b.Source) })
	return out
}

// linuxHost is the analysis view of a Linux Snapshot.
type linuxHost struct {
	source   string
	payload  *snapshotv1.LinuxPayload
	userLink *analysisv1.Link
}

// awsIdentity is the analysis view of one AWS Identity in an AWS Snapshot.
type awsIdentity struct {
	identity *snapshotv1.AwsIdentity
	link     *analysisv1.Link
	grants   []permission
}

type permission struct {
	awspolicy.Grant
	link *analysisv1.Link
}

// hop is an Identity Hop from a Linux user to an AWS Identity.
type hop struct {
	link *analysisv1.Link
	to   *awsIdentity
}

// readSnapshots reads the Snapshot of each Environment in the manifest, and
// rejects any that does not match the Environment identity the manifest
// expects.
func readSnapshots(files fs.FS, envs []manifest.Environment) ([]*linuxHost, []*awsIdentity, error) {
	var hosts []*linuxHost
	var identities []*awsIdentity
	for _, env := range envs {
		content, err := limits.ReadFile(files, env.Snapshot, limits.MaxSnapshotBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("environments[%d].snapshot: %w", env.Index, err)
		}
		source := env.Snapshot
		snap, err := snapshot.Parse(source, content)
		if err != nil {
			return nil, nil, err
		}
		if err := checkEnvironmentIdentity(source, env, snap); err != nil {
			return nil, nil, err
		}
		switch p := snap.Payload.(type) {
		case *snapshotv1.Snapshot_Linux:
			user := p.Linux.GetAgentUser()
			hosts = append(hosts, &linuxHost{
				source:  source,
				payload: p.Linux,
				userLink: link(analysisv1.LinkKind_LINK_KIND_IDENTITY,
					fmt.Sprintf("Linux user %s (uid %d)", user.GetName(), user.GetUid()),
					source, "$.linux.agentUser"),
			})
		case *snapshotv1.Snapshot_Aws:
			for i, id := range p.Aws.GetIdentities() {
				ident, err := readAWSIdentity(source, fmt.Sprintf("$.aws.identities[%d]", i), id)
				if err != nil {
					return nil, nil, err
				}
				identities = append(identities, ident)
			}
		}
	}
	return hosts, identities, nil
}

func readAWSIdentity(source, location string, id *snapshotv1.AwsIdentity) (*awsIdentity, error) {
	ident := &awsIdentity{
		identity: id,
		link:     link(analysisv1.LinkKind_LINK_KIND_IDENTITY, awsIdentityLabel(id.GetArn()), source, location),
	}
	for i, policy := range id.GetPolicies() {
		docLocation := fmt.Sprintf("%s.policies[%d].document", location, i)
		grants, err := awspolicy.Grants(policy.GetDocument())
		if err != nil {
			return nil, fmt.Errorf("%s: %s: %w", source, docLocation, err)
		}
		for _, g := range grants {
			ident.grants = append(ident.grants, permission{
				Grant: g,
				link: link(analysisv1.LinkKind_LINK_KIND_NATIVE_PERMISSION,
					fmt.Sprintf("Allow %s on %s", g.Action, g.Resource),
					source, docLocation+strings.TrimPrefix(g.Location, "$")),
			})
		}
	}
	return ident, nil
}

func awsIdentityLabel(arn string) string {
	switch {
	case strings.Contains(arn, ":role/"):
		return "AWS role " + arn
	case strings.Contains(arn, ":user/"):
		return "AWS user " + arn
	default:
		return "AWS Identity " + arn
	}
}

// credentialHops returns the Identity Hops from a host's agent user to AWS
// Identities, through AWS credential files that user can read.
func credentialHops(host *linuxHost, identities []*awsIdentity) ([]hop, error) {
	user := host.payload.GetAgentUser()
	var hops []hop
	for i, file := range host.payload.GetCredentialFiles() {
		if file.GetKind() != snapshotv1.CredentialKind_CREDENTIAL_KIND_AWS_SHARED_CREDENTIALS {
			continue
		}
		readable, err := canRead(user, file)
		if err != nil {
			return nil, fmt.Errorf("%s: invalid Snapshot: $.linux.credentialFiles[%d].mode: %w", host.source, i, err)
		}
		if !readable {
			continue
		}
		for j, profile := range file.GetAwsProfiles() {
			for _, ident := range identities {
				if profile.GetAccessKeyIdFingerprint() == "" ||
					!slices.Contains(ident.identity.GetAccessKeyIdFingerprints(), profile.GetAccessKeyIdFingerprint()) {
					continue
				}
				hops = append(hops, hop{
					link: link(analysisv1.LinkKind_LINK_KIND_IDENTITY_HOP,
						fmt.Sprintf("can read AWS credential file %s (profile %s)", file.GetPath(), profile.GetName()),
						host.source, fmt.Sprintf("$.linux.credentialFiles[%d].awsProfiles[%d]", i, j)),
					to: ident,
				})
			}
		}
	}
	return hops, nil
}

// canRead reports whether a Linux user can read a file, from the file's
// owner, group, and permission bits.
func canRead(user *snapshotv1.LinuxUser, file *snapshotv1.CredentialFile) (bool, error) {
	mode, err := strconv.ParseUint(file.GetMode(), 8, 12)
	if err != nil {
		return false, fmt.Errorf("%q is not an octal permission mode", file.GetMode())
	}
	switch {
	case user.GetUid() == 0:
		return true, nil
	case user.GetUid() == file.GetOwnerUid():
		return mode&0o400 != 0, nil
	case slices.ContainsFunc(user.GetGroups(), func(g *snapshotv1.LinuxGroup) bool { return g.GetGid() == file.GetGroupGid() }):
		return mode&0o040 != 0, nil
	default:
		return mode&0o004 != 0, nil
	}
}

func link(kind analysisv1.LinkKind, label, source, location string) *analysisv1.Link {
	return &analysisv1.Link{
		Kind:     kind,
		Label:    label,
		Evidence: &analysisv1.Evidence{Source: source, Location: location},
	}
}
