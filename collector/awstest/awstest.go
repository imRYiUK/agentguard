// Package awstest is a fake AWS account for testing the Collector. It
// implements aws.API from a description of the account, answers like AWS
// (NoSuchEntity for what is not there, and a configured error for what the
// credentials are denied), and records every call it receives so a test can
// check that the Collector only reads.
package awstest

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/imRYiUK/agentguard/collector/aws"
)

// Failure is an error the fake returns.
type Failure struct {
	Code string `json:"code"`
	// Message is returned in the error. The Collector must never record it.
	Message string `json:"message,omitempty"`
}

// Principal is an IAM user, role, or group.
type Principal struct {
	// ARN is the principal's ARN (a role's includes its path).
	ARN string `json:"arn,omitempty"`
	// Groups are the names of the groups a user is in.
	Groups []string `json:"groups,omitempty"`
	// Attached are the managed policies attached to it.
	Attached []aws.AttachedPolicy `json:"attached,omitempty"`
	// Inline are its inline policies: name to JSON document.
	Inline map[string]json.RawMessage `json:"inline,omitempty"`
}

// ManagedPolicy is a managed policy and its versions.
type ManagedPolicy struct {
	DefaultVersion string                     `json:"defaultVersion"`
	Versions       map[string]json.RawMessage `json:"versions"`
}

// Account describes a fake AWS account and the credentials used on it.
type Account struct {
	// AccessKeyID is the access key ID of the credentials.
	AccessKeyID string `json:"accessKeyId"`
	// SecretAccessKey and SessionToken are held by the fake only so a test
	// can check they never reach a Snapshot. The Collector cannot read them
	// through aws.API.
	SecretAccessKey string `json:"secretAccessKey,omitempty"`
	SessionToken    string `json:"sessionToken,omitempty"`

	Caller aws.CallerIdentity `json:"caller"`
	// Users, Roles, and Groups are keyed by name.
	Users  map[string]Principal `json:"users,omitempty"`
	Roles  map[string]Principal `json:"roles,omitempty"`
	Groups map[string]Principal `json:"groups,omitempty"`
	// Managed is keyed by policy ARN.
	Managed map[string]ManagedPolicy `json:"managed,omitempty"`
	// Failures are calls that fail, keyed by call name, such as
	// "iam:ListRolePolicies", or "iam:GetRolePolicy ops/audit" to fail one
	// target only.
	Failures map[string]Failure `json:"failures,omitempty"`
	// KeyUnavailable makes AccessKeyID fail.
	KeyUnavailable bool `json:"keyUnavailable,omitempty"`
}

// Load reads a fake account from a JSON file.
func Load(file string) (*Fake, error) {
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var a Account
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	return New(a), nil
}

// Fake is a fake AWS account. It implements aws.API.
type Fake struct {
	Account Account

	mu    sync.Mutex
	calls []string
}

// New returns a Fake of the account.
func New(a Account) *Fake { return &Fake{Account: a} }

// Calls returns the name of every AWS call the Collector made, in order,
// such as "iam:GetRole". AccessKeyID is not an AWS call and is not listed.
func (f *Fake) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

// call records a call and returns the configured failure for it, if any.
func (f *Fake) call(name, target string) error {
	f.mu.Lock()
	f.calls = append(f.calls, name)
	f.mu.Unlock()
	for _, key := range []string{name + " " + target, name} {
		if fail, ok := f.Account.Failures[key]; ok {
			return &aws.Error{Code: fail.Code, Message: fail.Message}
		}
	}
	return nil
}

func noSuchEntity(what string) error {
	return &aws.Error{Code: "NoSuchEntity", Message: what + " cannot be found"}
}

func (f *Fake) principal(kind aws.PrincipalKind, name string) (Principal, bool) {
	var m map[string]Principal
	switch kind {
	case aws.User:
		m = f.Account.Users
	case aws.Role:
		m = f.Account.Roles
	case aws.Group:
		m = f.Account.Groups
	}
	p, ok := m[name]
	return p, ok
}

// AccessKeyID implements aws.API.
func (f *Fake) AccessKeyID(context.Context) (string, error) {
	if f.Account.KeyUnavailable {
		return "", fmt.Errorf("no credentials; secret %s", f.Account.SecretAccessKey)
	}
	return f.Account.AccessKeyID, nil
}

// GetCallerIdentity implements aws.API.
func (f *Fake) GetCallerIdentity(context.Context) (aws.CallerIdentity, error) {
	if err := f.call("sts:GetCallerIdentity", ""); err != nil {
		return aws.CallerIdentity{}, err
	}
	return f.Account.Caller, nil
}

// GetRole implements aws.API.
func (f *Fake) GetRole(_ context.Context, name string) (string, error) {
	if err := f.call("iam:GetRole", name); err != nil {
		return "", err
	}
	p, ok := f.principal(aws.Role, name)
	if !ok {
		return "", noSuchEntity("role " + name)
	}
	return p.ARN, nil
}

// ListGroupsForUser implements aws.API.
func (f *Fake) ListGroupsForUser(_ context.Context, user string) ([]aws.IAMGroup, error) {
	if err := f.call("iam:ListGroupsForUser", user); err != nil {
		return nil, err
	}
	p, ok := f.principal(aws.User, user)
	if !ok {
		return nil, noSuchEntity("user " + user)
	}
	var out []aws.IAMGroup
	for _, name := range p.Groups {
		out = append(out, aws.IAMGroup{Name: name, ARN: f.Account.Groups[name].ARN})
	}
	return out, nil
}

// ListAttachedPolicies implements aws.API.
func (f *Fake) ListAttachedPolicies(_ context.Context, kind aws.PrincipalKind, name string) ([]aws.AttachedPolicy, error) {
	if err := f.call("iam:ListAttached"+string(kind)+"Policies", name); err != nil {
		return nil, err
	}
	p, ok := f.principal(kind, name)
	if !ok {
		return nil, noSuchEntity(strings.ToLower(string(kind)) + " " + name)
	}
	return slices.Clone(p.Attached), nil
}

// ListInlinePolicyNames implements aws.API.
func (f *Fake) ListInlinePolicyNames(_ context.Context, kind aws.PrincipalKind, name string) ([]string, error) {
	if err := f.call("iam:List"+string(kind)+"Policies", name); err != nil {
		return nil, err
	}
	p, ok := f.principal(kind, name)
	if !ok {
		return nil, noSuchEntity(strings.ToLower(string(kind)) + " " + name)
	}
	names := make([]string, 0, len(p.Inline))
	for n := range p.Inline {
		names = append(names, n)
	}
	sort.Strings(names)
	return names, nil
}

// GetInlinePolicy implements aws.API.
func (f *Fake) GetInlinePolicy(_ context.Context, kind aws.PrincipalKind, name, policy string) (string, error) {
	if err := f.call("iam:Get"+string(kind)+"Policy", name+"/"+policy); err != nil {
		return "", err
	}
	p, ok := f.principal(kind, name)
	if !ok {
		return "", noSuchEntity(strings.ToLower(string(kind)) + " " + name)
	}
	doc, ok := p.Inline[policy]
	if !ok {
		return "", noSuchEntity("policy " + policy)
	}
	return string(doc), nil
}

// GetPolicy implements aws.API.
func (f *Fake) GetPolicy(_ context.Context, arn string) (string, error) {
	if err := f.call("iam:GetPolicy", arn); err != nil {
		return "", err
	}
	m, ok := f.Account.Managed[arn]
	if !ok {
		return "", noSuchEntity("policy " + arn)
	}
	return m.DefaultVersion, nil
}

// GetPolicyVersion implements aws.API.
func (f *Fake) GetPolicyVersion(_ context.Context, arn, versionID string) (string, error) {
	if err := f.call("iam:GetPolicyVersion", arn); err != nil {
		return "", err
	}
	doc, ok := f.Account.Managed[arn].Versions[versionID]
	if !ok {
		return "", noSuchEntity("policy version " + versionID)
	}
	return string(doc), nil
}

var _ aws.API = (*Fake)(nil)
