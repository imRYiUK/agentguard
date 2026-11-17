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
	"time"

	analysisv1 "github.com/imRYiUK/agentguard/proto/gen/go/agentguard/analysis/v1"
	snapshotv1 "github.com/imRYiUK/agentguard/proto/gen/go/agentguard/snapshot/v1"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/imRYiUK/agentguard/core/internal/agentconfig"
	"github.com/imRYiUK/agentguard/core/internal/awspolicy"
	"github.com/imRYiUK/agentguard/core/internal/hopsearch"
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
	// Now is the time Snapshot ages are measured against. The zero value
	// means the current time. Fixing it makes a result reproducible.
	Now time.Time
	// StalenessThreshold is the age past which a Snapshot is a Stale
	// Snapshot. The zero value means DefaultStalenessThreshold.
	StalenessThreshold time.Duration
}

// Analyze returns the Reach Paths found in the Analysis Input. The same
// input, with the same Now and StalenessThreshold, always gives the same
// result.
func Analyze(in Input) (*analysisv1.AnalysisResult, error) {
	if in.Now.IsZero() {
		in.Now = time.Now()
	}
	if in.StalenessThreshold < 0 {
		return nil, fmt.Errorf("the staleness threshold must be positive, got %s", in.StalenessThreshold)
	}
	if in.StalenessThreshold == 0 {
		in.StalenessThreshold = DefaultStalenessThreshold
	}
	m, manifestBytes, err := readManifest(in.Files)
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
	linux, aws, snaps, err := readSnapshots(in.Files, m.Environments)
	if err != nil {
		return nil, err
	}

	budget := awspolicy.NewBudget(limits.MaxPolicyEvalSteps)
	markStale(snaps, in.Now, in.StalenessThreshold)
	result := &analysisv1.AnalysisResult{
		ImpactMappingVersion: impacts.Version,
		RulesVersion:         RulesVersion,
		AnalysisInput:        analysisInput(in, m, manifestBytes, snaps),
		SecondaryFindings:    secondaryFindings(m.Agent.Name, tools, filesystem, aws),
	}
	pathAt := map[string]int{} // Reach Path Fingerprint to its index in result.ReachPaths
	sc := newScorer(snaps, in.StalenessThreshold, m.ResourceSensitivities)
	result.BlindSpots = sc.blindSpots()
	for _, host := range linux {
		if err := host.findChains(aws); err != nil {
			return nil, err
		}
	}
	result.SecondaryFindings = append(result.SecondaryFindings,
		bindingMismatches(m, linux, aws)...)
	for _, tool := range tools {
		toolLink := link(analysisv1.LinkKind_LINK_KIND_TOOL,
			fmt.Sprintf("shell Tool (MCP server %s)", tool.Server), tool.Source, tool.Location)
		for _, host := range linux {
			for _, chain := range host.chains {
				to := chain[len(chain)-1].Via.identity
				if to == nil {
					continue
				}
				perms, err := to.permissions(impacts, budget)
				if err != nil {
					return nil, err
				}
				for _, perm := range perms {
					links := []*analysisv1.Link{toolLink, host.userLink}
					for _, h := range chain {
						links = append(links, h.Via.link, h.Via.toLink)
					}
					links = append(links, perm.link, perm.impact)
					structure := []string{"deployment", m.Agent.Name, "tool", "mcp-shell:" + tool.Server,
						"identity", "linux:" + host.identityKey + ":" + host.payload.GetAgentUser().GetName()}
					for _, h := range chain {
						structure = append(structure, "hop", h.Via.how, "identity", h.Via.to)
					}
					structure = append(structure, "permission", perm.action, "resource", perm.onResource, "impact", perm.impactName)
					p, err := sc.path(m.Agent.Name, structure, links, perm)
					if err != nil {
						return nil, err
					}
					// Two statements can grant the same Native Permission. They
					// are one finding with one fingerprint, and the more
					// certain grant is kept.
					if at, dup := pathAt[p.Fingerprint]; dup {
						if result.ReachPaths[at].Confidence == analysisv1.Confidence_CONFIDENCE_REDUCED &&
							p.Confidence == analysisv1.Confidence_CONFIDENCE_HIGH {
							result.ReachPaths[at] = p
						}
						continue
					}
					pathAt[p.Fingerprint] = len(result.ReachPaths)
					result.ReachPaths = append(result.ReachPaths, p)
				}
			}
		}
	}
	return result, nil
}

// readManifest returns the parsed Agent Manifest and the bytes it was parsed
// from.
func readManifest(files fs.FS) (*manifest.Manifest, []byte, error) {
	content, err := limits.ReadFile(files, ManifestFile, limits.MaxConfigBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("reading the Agent Manifest: %w", err)
	}
	m, err := manifest.Parse(ManifestFile, content)
	if err != nil {
		return nil, nil, err
	}
	return m, content, nil
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
	// environment is the name of the Environment in the manifest.
	environment string
	source      string
	// identityKey is the host's provider-native identity, which the manifest
	// and the Snapshot agree on: its machine ID, or else its SSH host key
	// fingerprint. The Environment's name is only a label.
	identityKey string
	payload     *snapshotv1.LinuxPayload
	userLink    *analysisv1.Link
	// agentHops are the credential-file hops the agent user can take
	// itself, without any inferred step.
	agentHops []hopsearch.Hop[step]
	// chains are the Identity Hop chains leading away from the agent user.
	chains [][]hopsearch.Hop[step]
}

// awsIdentity is the analysis view of one AWS Identity in an AWS Snapshot.
type awsIdentity struct {
	// environment is the name of the Environment in the manifest.
	environment string
	source      string
	location    string
	identity    *snapshotv1.AwsIdentity
	link        *analysisv1.Link
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
	// resource is the resource pattern the permission is on, and impactName
	// the Impact attached to it, for severity and the Reach Path
	// Fingerprint.
	resource   string
	impactName string
	// action and onResource state the Native Permission as the policy does,
	// for the Reach Path Fingerprint.
	action, onResource string
}

// readSnapshots reads the Snapshot of each Environment in the manifest, and
// rejects any that does not match the Environment identity the manifest
// expects.
func readSnapshots(files fs.FS, envs []manifest.Environment) ([]*linuxHost, []*awsIdentity, []*snapshotInfo, error) {
	var hosts []*linuxHost
	var identities []*awsIdentity
	var infos []*snapshotInfo
	for _, env := range envs {
		content, err := limits.ReadFile(files, env.Snapshot, limits.MaxSnapshotBytes)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("environments[%d].snapshot: %w", env.Index, err)
		}
		source := env.Snapshot
		snap, err := snapshot.Parse(source, content)
		if err != nil {
			return nil, nil, nil, err
		}
		if err := checkEnvironmentIdentity(source, env, snap); err != nil {
			return nil, nil, nil, err
		}
		infos = append(infos, &snapshotInfo{
			environment: env.Name,
			source:      source,
			id:          snap.GetSnapshotId(),
			collectedAt: snap.GetCollectedAt().AsTime(),
			blindSpots:  snap.GetBlindSpots(),
		})
		switch p := snap.Payload.(type) {
		case *snapshotv1.Snapshot_Linux:
			user := p.Linux.GetAgentUser()
			id := snap.GetEnvironment().GetLinux()
			key := id.GetMachineId()
			if key == "" {
				key = id.GetSshHostKeyFingerprint()
			}
			hosts = append(hosts, &linuxHost{
				environment: env.Name,
				source:      source,
				identityKey: key,
				payload:     p.Linux,
				userLink: bindingLink(analysisv1.BindingOrigin_BINDING_ORIGIN_DISCOVERED,
					fmt.Sprintf("Linux user %s (uid %d)", user.GetName(), user.GetUid()),
					source, "$.linux.agentUser"),
			})
		case *snapshotv1.Snapshot_Aws:
			for i, id := range p.Aws.GetIdentities() {
				ident, err := readAWSIdentity(env.Name, source, fmt.Sprintf("$.aws.identities[%d]", i), id)
				if err != nil {
					return nil, nil, nil, err
				}
				identities = append(identities, ident)
			}
		}
	}
	return hosts, identities, infos, nil
}

func readAWSIdentity(environment, source, location string, id *snapshotv1.AwsIdentity) (*awsIdentity, error) {
	ident := &awsIdentity{
		environment: environment,
		source:      source,
		location:    location,
		identity:    id,
		link:        bindingLink(analysisv1.BindingOrigin_BINDING_ORIGIN_DISCOVERED, awsIdentityLabel(id.GetArn()), source, location),
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
				link:       a.permissionLink(g),
				impact:     link(analysisv1.LinkKind_LINK_KIND_IMPACT, impact.Unknown, impacts.Source(), impact.NoMappingLocation),
				resource:   grantResourcePattern(g),
				impactName: impact.Unknown,
				action:     grantActionKey(g),
				onResource: grantResourceKey(g),
			})
			continue
		}
		for _, f := range fs {
			a.perms = append(a.perms, permission{
				link:       a.permissionLink(f.grant),
				impact:     link(analysisv1.LinkKind_LINK_KIND_IMPACT, f.impact, impacts.Source(), impacts.Location(f.mapping)),
				resource:   grantResourcePattern(f.grant),
				impactName: f.impact,
				action:     grantActionKey(f.grant),
				onResource: grantResourceKey(f.grant),
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

// grantActionKey is grantAction with the NotAction entries sorted, so the
// order a policy lists them in does not change the Reach Path Fingerprint.
func grantActionKey(g awspolicy.Grant) string {
	if len(g.Statement.NotActions) > 0 {
		return "all actions except " + strings.Join(sorted(g.Statement.NotActions), ", ")
	}
	return g.Action
}

// grantResourceKey is grantResource with the NotResource entries sorted.
func grantResourceKey(g awspolicy.Grant) string {
	if len(g.Statement.NotResources) > 0 {
		return "all resources except " + strings.Join(sorted(g.Statement.NotResources), ", ")
	}
	return g.Resource
}

func sorted(list []string) []string {
	out := slices.Clone(list)
	slices.Sort(out)
	return out
}

// grantResourcePattern is the resource pattern a Grant is on. A NotResource
// grant reaches every resource but the ones it lists, so it is "*": reaching
// too much is the safe error.
func grantResourcePattern(g awspolicy.Grant) string {
	if g.Resource == "" {
		return "*"
	}
	return g.Resource
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

// bindingLink returns an Identity link: an Identity Binding with its origin.
func bindingLink(origin analysisv1.BindingOrigin, label, source, location string) *analysisv1.Link {
	l := link(analysisv1.LinkKind_LINK_KIND_IDENTITY, label, source, location)
	l.Origin = origin
	return l
}

func link(kind analysisv1.LinkKind, label, source, location string) *analysisv1.Link {
	return &analysisv1.Link{
		Kind:       kind,
		Label:      label,
		Evidence:   &analysisv1.Evidence{Source: source, Location: location},
		Confidence: analysisv1.Confidence_CONFIDENCE_HIGH,
	}
}
