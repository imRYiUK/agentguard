package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/imRYiUK/agentguard/collector/internal/fingerprint"
	"github.com/imRYiUK/agentguard/collector/internal/snapshotjson"
	snapshotv1 "github.com/imRYiUK/agentguard/proto/gen/go/agentguard/snapshot/v1"
)

// SchemaVersion is the Snapshot schema version the Collector writes.
const SchemaVersion = "1"

// Limits on what the Collector records, so a hostile or broken account
// cannot make it use unbounded memory or write a Snapshot AgentGuard refuses
// to read. They match the limits AgentGuard applies when it reads one.
const (
	// maxPolicyDocumentBytes is the size limit of one policy document. AWS
	// itself caps a policy at 6,144 characters.
	maxPolicyDocumentBytes = 256 << 10
	// maxPolicyDepth is the nesting limit of a policy document.
	maxPolicyDepth = 16
	// maxPoliciesPerPrincipal is the number of policies recorded for one
	// user, role, or group. AWS allows 20 attached ones by default.
	maxPoliciesPerPrincipal = 128
	// maxGroups is the number of groups recorded for a user. AWS allows a
	// user to be in 10 by default.
	maxGroups = 32
)

// Options are the facts about a collection that do not come from AWS.
type Options struct {
	// Version is the Collector's version.
	Version string
	// Now is the collection time.
	Now time.Time
	// SnapshotID is the unique ID of the Snapshot.
	SnapshotID string
}

// Collect reads the AWS account the credentials behind api belong to, and
// returns a Snapshot of the Identity they resolve to and its identity-based
// policies (managed, inline, and those of its groups). It fails only when it
// cannot establish which account it is looking at, because a Snapshot
// without an identity cannot be matched to an Environment. Everything else
// it is denied or cannot read becomes a Blind Spot.
//
// The Identity is the one the credentials found on the host resolve to: run
// the Collector with the credentials the agent uses.
func Collect(ctx context.Context, api API, opts Options) (*snapshotv1.Snapshot, error) {
	switch {
	case opts.Version == "":
		return nil, errors.New("collect: the Collector version is required")
	case opts.SnapshotID == "":
		return nil, errors.New("collect: the Snapshot ID is required")
	case opts.Now.IsZero():
		return nil, errors.New("collect: the collection time is required")
	}
	c := &collector{api: api, managed: map[string]*snapshotv1.AwsPolicy{}}

	caller, err := api.GetCallerIdentity(ctx)
	if err != nil {
		why := "no usable credentials were found, or AWS could not be reached"
		var ae *Error
		if errors.As(err, &ae) {
			why = reason(err)
		}
		return nil, fmt.Errorf("collect: cannot resolve the credentials to an Identity (sts:GetCallerIdentity): %s", why)
	}
	if !accountID.MatchString(caller.Account) {
		return nil, errors.New("collect: AWS returned an account ID that is not 12 digits")
	}
	if !arnPattern.MatchString(caller.ARN) {
		return nil, errors.New("collect: AWS returned a caller ARN that is not an ARN")
	}

	identity := c.identity(ctx, caller)
	c.blindSpots = append(c.blindSpots, uncollectedPolicyTypes()...)

	snap := &snapshotv1.Snapshot{
		SchemaVersion:    SchemaVersion,
		SnapshotId:       opts.SnapshotID,
		CollectorVersion: opts.Version,
		CollectedAt:      timestamppb.New(opts.Now.UTC()),
		CollectedBy:      caller.ARN,
		Environment: &snapshotv1.EnvironmentIdentity{
			Identity: &snapshotv1.EnvironmentIdentity_Aws{Aws: &snapshotv1.AwsEnvironmentIdentity{AccountId: caller.Account}},
		},
		BlindSpots: c.blindSpots,
		Payload:    &snapshotv1.Snapshot_Aws{Aws: &snapshotv1.AwsPayload{Identities: []*snapshotv1.AwsIdentity{identity}}},
	}
	if err := c.checkNoSecrets(snap); err != nil {
		return nil, err
	}
	return snap, nil
}

// MarshalJSON writes a Snapshot as Protobuf canonical JSON, indented and
// byte-stable.
func MarshalJSON(snap *snapshotv1.Snapshot) ([]byte, error) { return snapshotjson.Marshal(snap) }

var (
	accountID  = regexp.MustCompile(`^[0-9]{12}$`)
	arnPattern = regexp.MustCompile(`^arn:aws[a-z-]*:[a-z0-9-]+:[a-z0-9-]*:[0-9]*:.+$`)
	// errorCode is what an AWS error code looks like: a CamelCase word, such
	// as AccessDenied or NoSuchEntity. Anything else is not recorded, so a
	// code cannot be used to smuggle text into a Snapshot.
	errorCode = regexp.MustCompile(`^[A-Z][A-Za-z]{2,47}$`)
)

// collector holds the state of one collection.
type collector struct {
	api        API
	blindSpots []*snapshotv1.BlindSpot
	// accessKeyID is the access key ID of the credentials. It is kept only
	// to check, at the end, that it did not reach the Snapshot.
	accessKeyID string
	// managed caches managed policies by ARN, so one attached to several
	// principals is read once. A policy that could not be read is nil.
	managed map[string]*snapshotv1.AwsPolicy
}

func (c *collector) blind(attempted, why string) {
	c.blindSpots = append(c.blindSpots, &snapshotv1.BlindSpot{Attempted: attempted, Reason: why})
}

// blindCall records a failed AWS call as a Blind Spot naming the call, what
// it was for, and AWS's error code.
func (c *collector) blindCall(call, target string, err error) {
	attempted := call
	if target != "" {
		attempted += " " + target
	}
	c.blind(attempted, reason(err))
}

// reason describes why a call failed. For an AWS error it is the error code
// and nothing else, because AWS's message is free text that could echo
// anything. Any other error is not described at all.
func reason(err error) string {
	var ae *Error
	if errors.As(err, &ae) && errorCode.MatchString(ae.Code) {
		return ae.Code
	}
	return "the call failed"
}

// uncollectedPolicyTypes are the Blind Spots every AWS Snapshot has: the
// kinds of policy that can limit what an Identity may do, which the
// Collector does not read. Without them analysis would read the absence of
// a Deny as the absence of any limit.
func uncollectedPolicyTypes() []*snapshotv1.BlindSpot {
	const why = "not collected: the Collector does not read this policy type, so a limit it sets is not applied"
	var out []*snapshotv1.BlindSpot
	for _, what := range []string{
		"service control policies (SCPs)",
		"resource control policies (RCPs)",
		"permission boundaries",
		"session policies",
		"resource-based policies",
	} {
		out = append(out, &snapshotv1.BlindSpot{Attempted: "collect " + what, Reason: why})
	}
	return out
}

// checkNoSecrets is a last guard: it fails the collection if the access key
// ID reached the Snapshot, which records it only as a fingerprint. Nothing
// copies it there, so this is defence in depth against a future bug.
func (c *collector) checkNoSecrets(snap *snapshotv1.Snapshot) error {
	if c.accessKeyID == "" {
		return nil
	}
	out, err := protojson.Marshal(snap)
	if err != nil {
		return err
	}
	if strings.Contains(string(out), c.accessKeyID) {
		return errors.New("collect: internal error: the Snapshot would contain an access key ID, so it was not written")
	}
	return nil
}

// identity records the Identity the caller is, with its policies.
func (c *collector) identity(ctx context.Context, caller CallerIdentity) *snapshotv1.AwsIdentity {
	id := &snapshotv1.AwsIdentity{Arn: caller.ARN}

	key, err := c.api.AccessKeyID(ctx)
	if err != nil || key == "" {
		c.blind("read the access key ID of the credentials", "the credentials hold none that can be read")
	} else {
		c.accessKeyID = key
		id.AccessKeyIdFingerprints = []string{fingerprint.Of([]byte(key))}
	}

	kind, name, partition, ok := parsePrincipal(caller.ARN)
	switch {
	case !ok:
		c.blind("collect the policies of "+caller.ARN,
			"not supported: only IAM users and assumed roles are collected, and these credentials resolve to something else")
		return id
	case kind == Role:
		id.Arn = c.roleARN(ctx, caller, name, partition)
	}

	id.Policies = c.policies(ctx, kind, name)
	if kind == User {
		id.Groups = c.groups(ctx, name)
	}
	return id
}

// roleARN returns the ARN of the role behind an assumed-role session. The
// session's own ARN omits the role's path, so it asks AWS for the role; if it
// is denied it falls back to the ARN without a path, and says so.
func (c *collector) roleARN(ctx context.Context, caller CallerIdentity, name, partition string) string {
	fallback := fmt.Sprintf("arn:%s:iam::%s:role/%s", partition, caller.Account, name)
	arn, err := c.api.GetRole(ctx, name)
	if err != nil {
		c.blindCall("iam:GetRole", "role "+name, err)
		c.blind("resolve the path of role "+name, "its ARN was built without a path, so it differs from the real ARN if the role has one")
		return fallback
	}
	prefix := "arn:" + partition + ":iam::" + caller.Account + ":role/"
	if !strings.HasPrefix(arn, prefix) || path.Base(arn) != name {
		c.blind("iam:GetRole role "+name, "AWS returned an ARN that is not this role's")
		return fallback
	}
	return arn
}

// parsePrincipal reads a caller ARN: the kind of principal (a user, or the
// role behind an assumed-role session), its name, and the ARN's partition.
func parsePrincipal(arn string) (kind PrincipalKind, name, partition string, ok bool) {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 {
		return "", "", "", false
	}
	partition, service, resource := parts[1], parts[2], parts[5]
	switch {
	case service == "iam" && strings.HasPrefix(resource, "user/"):
		return User, resource[strings.LastIndex(resource, "/")+1:], partition, true
	case service == "sts" && strings.HasPrefix(resource, "assumed-role/"):
		segments := strings.Split(resource, "/")
		if len(segments) != 3 || segments[1] == "" {
			return "", "", "", false
		}
		return Role, segments[1], partition, true
	}
	return "", "", "", false
}

// policies reads the managed and inline policies attached to a principal.
func (c *collector) policies(ctx context.Context, kind PrincipalKind, name string) []*snapshotv1.AwsPolicy {
	target := strings.ToLower(string(kind)) + " " + name
	var out []*snapshotv1.AwsPolicy

	attached, err := c.api.ListAttachedPolicies(ctx, kind, name)
	if err != nil {
		c.blindCall("iam:ListAttached"+string(kind)+"Policies", target, err)
	}
	slices.SortFunc(attached, func(a, b AttachedPolicy) int { return strings.Compare(a.ARN, b.ARN) })
	for _, a := range attached {
		if len(out) >= maxPoliciesPerPrincipal {
			c.blind("collect the policies of "+target, fmt.Sprintf("only the first %d policies were recorded", maxPoliciesPerPrincipal))
			return out
		}
		if p := c.managedPolicy(ctx, a); p != nil {
			out = append(out, p)
		}
	}

	names, err := c.api.ListInlinePolicyNames(ctx, kind, name)
	if err != nil {
		c.blindCall("iam:List"+string(kind)+"Policies", target, err)
	}
	slices.Sort(names)
	for _, policy := range names {
		if len(out) >= maxPoliciesPerPrincipal {
			c.blind("collect the policies of "+target, fmt.Sprintf("only the first %d policies were recorded", maxPoliciesPerPrincipal))
			return out
		}
		doc, err := c.api.GetInlinePolicy(ctx, kind, name, policy)
		if err != nil {
			c.blindCall("iam:Get"+string(kind)+"Policy", target+", policy "+policy, err)
			continue
		}
		if s := c.document("inline policy "+policy+" of "+target, doc); s != nil {
			out = append(out, &snapshotv1.AwsPolicy{Name: policy, Document: s, Kind: snapshotv1.PolicyKind_POLICY_KIND_INLINE})
		}
	}
	return out
}

// managedPolicy reads a managed policy's default version, once per policy.
func (c *collector) managedPolicy(ctx context.Context, a AttachedPolicy) *snapshotv1.AwsPolicy {
	if p, done := c.managed[a.ARN]; done {
		return p
	}
	c.managed[a.ARN] = nil
	version, err := c.api.GetPolicy(ctx, a.ARN)
	if err != nil {
		c.blindCall("iam:GetPolicy", a.ARN, err)
		return nil
	}
	doc, err := c.api.GetPolicyVersion(ctx, a.ARN, version)
	if err != nil {
		c.blindCall("iam:GetPolicyVersion", a.ARN, err)
		return nil
	}
	s := c.document("managed policy "+a.ARN, doc)
	if s == nil {
		return nil
	}
	p := &snapshotv1.AwsPolicy{Name: a.Name, Document: s, Kind: snapshotv1.PolicyKind_POLICY_KIND_MANAGED, Arn: a.ARN}
	c.managed[a.ARN] = p
	return p
}

// groups reads the groups a user is in and their policies.
func (c *collector) groups(ctx context.Context, user string) []*snapshotv1.AwsGroup {
	listed, err := c.api.ListGroupsForUser(ctx, user)
	if err != nil {
		c.blindCall("iam:ListGroupsForUser", "user "+user, err)
		return nil
	}
	slices.SortFunc(listed, func(a, b IAMGroup) int { return strings.Compare(a.ARN, b.ARN) })
	if len(listed) > maxGroups {
		c.blind("collect the groups of user "+user, fmt.Sprintf("only the first %d groups were recorded", maxGroups))
		listed = listed[:maxGroups]
	}
	var out []*snapshotv1.AwsGroup
	for _, g := range listed {
		out = append(out, &snapshotv1.AwsGroup{Arn: g.ARN, Name: g.Name, Policies: c.policies(ctx, Group, g.Name)})
	}
	return out
}

// document turns a policy document into the Snapshot's form. It returns nil,
// with a Blind Spot, for a document the Collector must not record: one that
// is not a JSON object, is too large or too deeply nested for AgentGuard to
// read, or contains something that looks like a secret.
func (c *collector) document(what, doc string) *structpb.Struct {
	fail := func(why string) *structpb.Struct {
		c.blind("record the "+what, why)
		return nil
	}
	if len(doc) > maxPolicyDocumentBytes {
		return fail(fmt.Sprintf("the document is larger than %d bytes", maxPolicyDocumentBytes))
	}
	if jsonDepth(doc) > maxPolicyDepth {
		return fail(fmt.Sprintf("the document nests deeper than %d levels", maxPolicyDepth))
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(doc), &v); err != nil || v == nil {
		return fail("the document is not a JSON object")
	}
	if looksSecret(v) {
		return fail("the document contains a value that looks like a secret, so it was not recorded")
	}
	s, err := structpb.NewStruct(v)
	if err != nil {
		return fail("the document cannot be represented")
	}
	return s
}

// jsonDepth returns how deeply a JSON text nests, without parsing it.
func jsonDepth(doc string) int {
	depth, deepest := 0, 0
	inString, escaped := false, false
	for i := 0; i < len(doc); i++ {
		c := doc[i]
		if inString {
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '{', '[':
			depth++
			deepest = max(deepest, depth)
		case '}', ']':
			depth--
		}
	}
	return deepest
}
