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
	filesystem, err := agentconfig.BroadFilesystemTools(configFiles(mcpConfigs), configFiles(settings))
	if err != nil {
		return nil, err
	}
	linux, aws, err := readSnapshots(in.Files, m.Environments)
	if err != nil {
		return nil, err
	}

	budget := awspolicy.NewBudget(limits.MaxPolicyEvalSteps)
	result := &analysisv1.AnalysisResult{
		ImpactMappingVersion: impacts.Version,
		SecondaryFindings:    secondaryFindings(m.Agent.Name, tools, filesystem, aws),
	}
	for _, tool := range tools {
		toolLink := link(analysisv1.LinkKind_LINK_KIND_TOOL,
			fmt.Sprintf("shell Tool (MCP server %s)", tool.Server), tool.Source, tool.Location)
		for _, host := range linux {
			hops, err := credentialHops(host, aws)
			if err != nil {
				return nil, err
			}
			for _, hop := range hops {
				perms, err := hop.to.permissions(impacts, budget)
				if err != nil {
					return nil, err
				}
				for _, perm := range perms {
					links := []*analysisv1.Link{
						toolLink,
						host.userLink,
						hop.link,
						hop.to.link,
						perm.link,
						perm.impact,
					}
					result.ReachPaths = append(result.ReachPaths, &analysisv1.ReachPath{
						AgentDeployment: m.Agent.Name,
						Links:           links,
						Confidence:      weakest(links),
					})
				}
			}
		}
	}
	return result, nil
}

// weakest returns the lowest confidence among links, which is the confidence
// of the path they form.
func weakest(links []*analysisv1.Link) analysisv1.Confidence {
	out := analysisv1.Confidence_CONFIDENCE_HIGH
	for _, l := range links {
		if l.GetConfidence() == analysisv1.Confidence_CONFIDENCE_REDUCED {
			out = analysisv1.Confidence_CONFIDENCE_REDUCED
		}
	}
	return out
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
	source   string
	location string
	identity *snapshotv1.AwsIdentity
	link     *analysisv1.Link
	// statements are the statements of every policy that applies to the
	// Identity: its own managed and inline policies, then those of its
	// groups. A statement's Policy indexes policyLocations.
	statements []awspolicy.Statement
	// policyLocations are the JSONPaths in the Snapshot of the policy
	// documents the statements came from.
	policyLocations []string

	evaluated bool
	perms     []permission
}

// permission is one Native Permission of an Identity with the Impact
// attached to it, or the unknown Impact when no mapping names it.
type permission struct {
	link   *analysisv1.Link
	impact *analysisv1.Link
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
		source:   source,
		location: location,
		identity: id,
		link:     link(analysisv1.LinkKind_LINK_KIND_IDENTITY, awsIdentityLabel(id.GetArn()), source, location),
	}
	add := func(policies []*snapshotv1.AwsPolicy, listLocation string) error {
		for i, policy := range policies {
			docLocation := fmt.Sprintf("%s[%d].document", listLocation, i)
			stmts, err := awspolicy.Parse(policy.GetDocument())
			if err != nil {
				return fmt.Errorf("%s: %s: %w", source, docLocation, err)
			}
			for j := range stmts {
				stmts[j].Policy = len(ident.policyLocations)
			}
			ident.statements = append(ident.statements, stmts...)
			ident.policyLocations = append(ident.policyLocations, docLocation)
		}
		return nil
	}
	if err := add(id.GetPolicies(), location+".policies"); err != nil {
		return nil, err
	}
	for g, group := range id.GetGroups() {
		if err := add(group.GetPolicies(), fmt.Sprintf("%s.groups[%d].policies", location, g)); err != nil {
			return nil, err
		}
	}
	return ident, nil
}

// permissions returns the Native Permissions the Identity has, each with an
// Impact. A permission gets one entry per Impact the mapping table attaches to
// the actions it covers, or a single entry with the unknown Impact when the
// table names none of them. It evaluates all the Identity's policies together,
// so an explicit Deny in one removes an Allow in another.
func (a *awsIdentity) permissions(impacts *impact.Table, budget *awspolicy.Budget) ([]permission, error) {
	if a.evaluated {
		return a.perms, nil
	}
	fail := func(err error) ([]permission, error) {
		return nil, fmt.Errorf("%s: %s: %w", a.source, a.location, err)
	}

	// found collects, for each Native Permission, the Impacts the table gives
	// it, in table order. An Impact reached through several mapped actions
	// is kept once, from the grant with the most confidence.
	type permissionKey struct {
		statement        *awspolicy.Statement
		action, resource string
	}
	type found struct {
		impact  string
		mapping int
		grant   awspolicy.Grant
	}
	foundFor := map[permissionKey][]found{}
	for i, mapping := range impacts.Mappings {
		grants, err := awspolicy.Evaluate(a.statements, mapping.Action, budget)
		if err != nil {
			return fail(err)
		}
		for _, g := range grants {
			// An action only reaches the resources of its own service.
			if !awspolicy.ResourceInService(g.Resource, mapping.Service(), budget) {
				continue
			}
			key := permissionKey{g.Statement, g.Action, g.Resource}
			for _, imp := range mapping.Impacts {
				at := slices.IndexFunc(foundFor[key], func(f found) bool { return f.impact == imp })
				switch {
				case at < 0:
					foundFor[key] = append(foundFor[key], found{imp, i, g})
				case foundFor[key][at].grant.Conditional && !g.Conditional:
					foundFor[key][at] = found{imp, i, g}
				}
			}
		}
	}

	granted, err := awspolicy.Permissions(a.statements, budget)
	if err != nil {
		return fail(err)
	}
	if err := budget.Err(); err != nil {
		return fail(err)
	}
	for _, g := range granted {
		fs := foundFor[permissionKey{g.Statement, g.Action, g.Resource}]
		if len(fs) == 0 {
			a.perms = append(a.perms, permission{
				link:   a.permissionLink(g),
				impact: link(analysisv1.LinkKind_LINK_KIND_IMPACT, impact.Unknown, impacts.Source(), impact.NoMappingLocation),
			})
			continue
		}
		for _, f := range fs {
			a.perms = append(a.perms, permission{
				link:   a.permissionLink(f.grant),
				impact: link(analysisv1.LinkKind_LINK_KIND_IMPACT, f.impact, impacts.Source(), impacts.Location(f.mapping)),
			})
		}
	}
	a.evaluated = true
	return a.perms, nil
}

// statementLocation is the JSONPath in the Snapshot of a statement of one of
// the Identity's policies.
func (a *awsIdentity) statementLocation(st *awspolicy.Statement) string {
	return a.policyLocations[st.Policy] + strings.TrimPrefix(st.Location, "$")
}

// permissionLink returns the Native Permission link of a Grant.
func (a *awsIdentity) permissionLink(g awspolicy.Grant) *analysisv1.Link {
	l := link(analysisv1.LinkKind_LINK_KIND_NATIVE_PERMISSION,
		"Allow "+grantAction(g)+" on "+grantResource(g),
		a.source, a.statementLocation(g.Statement))
	if g.Conditional {
		l.Confidence = analysisv1.Confidence_CONFIDENCE_REDUCED
		l.ConfidenceReason = g.Reason
	}
	return l
}

// grantAction describes the actions a Grant allows, as the policy states them.
func grantAction(g awspolicy.Grant) string {
	if len(g.Statement.NotActions) > 0 {
		return "all actions except " + strings.Join(g.Statement.NotActions, ", ")
	}
	return g.Action
}

// grantResource describes the resources a Grant allows, as the policy states
// them.
func grantResource(g awspolicy.Grant) string {
	if len(g.Statement.NotResources) > 0 {
		return "all resources except " + strings.Join(g.Statement.NotResources, ", ")
	}
	return g.Resource
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
		Kind:       kind,
		Label:      label,
		Evidence:   &analysisv1.Evidence{Source: source, Location: location},
		Confidence: analysisv1.Confidence_CONFIDENCE_HIGH,
	}
}
