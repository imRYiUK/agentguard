// Package aws is the AWS Collector. Collect reads an AWS account, through
// the narrow API interface and with the credentials the Collector finds on
// the host, and returns a Snapshot of the Identity behind them.
//
// The Collector is read-only. It makes no call that creates, changes, or
// deletes anything, and API has no method that could. Whatever it is denied
// it records as a Blind Spot, and so are the policy types it does not
// collect, so that analysis does not treat them as absent. It never records
// a secret value: an access key ID is recorded as a fingerprint only, and
// the secret access key and session token never reach the Collector.
package aws

import "context"

// CallerIdentity is who AWS says the credentials belong to
// (sts:GetCallerIdentity).
type CallerIdentity struct {
	// Account is the 12-digit AWS account ID.
	Account string
	// ARN is the caller's ARN. For an assumed role it is the ARN of the
	// session, such as arn:aws:sts::123456789012:assumed-role/ops/session.
	ARN string
}

// PrincipalKind is a kind of IAM principal that has identity-based policies.
type PrincipalKind string

// The kinds of principal whose policies the Collector reads.
const (
	User  PrincipalKind = "User"
	Role  PrincipalKind = "Role"
	Group PrincipalKind = "Group"
)

// IAMGroup is an IAM group a user is a member of.
type IAMGroup struct {
	Name string
	ARN  string
}

// AttachedPolicy is a managed policy attached to a principal.
type AttachedPolicy struct {
	Name string
	ARN  string
}

// Error is an error returned by AWS. Only Code is ever recorded in a
// Snapshot: Message is free text that may echo anything.
type Error struct {
	// Code is the AWS error code, such as "AccessDenied".
	Code string
	// Message is AWS's description of the error.
	Message string
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// API is the whole of what the Collector can do to AWS: every method reads,
// and none writes. Lists are returned whole; the real implementation pages
// through them. A document is JSON text as AWS returns it, decoded from its
// URL encoding.
//
// A method that fails returns an *Error when AWS answered, so the Collector
// can record why.
type API interface {
	// AccessKeyID returns the access key ID of the credentials in use. It is
	// read from the local credential chain and is not an AWS call. It is the
	// only part of the credentials the Collector sees.
	AccessKeyID(ctx context.Context) (string, error)

	// GetCallerIdentity is sts:GetCallerIdentity.
	GetCallerIdentity(ctx context.Context) (CallerIdentity, error)
	// GetRole is iam:GetRole. It returns the role's ARN, which, unlike the
	// ARN of a session, includes the role's path.
	GetRole(ctx context.Context, name string) (arn string, err error)
	// ListGroupsForUser is iam:ListGroupsForUser.
	ListGroupsForUser(ctx context.Context, user string) ([]IAMGroup, error)
	// ListAttachedPolicies is iam:ListAttached{User,Role,Group}Policies.
	ListAttachedPolicies(ctx context.Context, kind PrincipalKind, name string) ([]AttachedPolicy, error)
	// ListInlinePolicyNames is iam:List{User,Role,Group}Policies.
	ListInlinePolicyNames(ctx context.Context, kind PrincipalKind, name string) ([]string, error)
	// GetInlinePolicy is iam:Get{User,Role,Group}Policy.
	GetInlinePolicy(ctx context.Context, kind PrincipalKind, name, policy string) (document string, err error)
	// GetPolicy is iam:GetPolicy. It returns the ID of the policy's default
	// version.
	GetPolicy(ctx context.Context, arn string) (defaultVersionID string, err error)
	// GetPolicyVersion is iam:GetPolicyVersion.
	GetPolicyVersion(ctx context.Context, arn, versionID string) (document string, err error)
}
