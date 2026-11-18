package aws

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

// maxPages is how many pages of one list the adapter reads. At the default
// page size it is far more than the Collector records, so a list this long
// is cut short and the Collector says so.
const maxPages = 10

// iamClient is the part of the IAM client the adapter uses: every method
// reads. The adapter cannot call anything else, because it holds no other
// method.
type iamClient interface {
	GetRole(context.Context, *iam.GetRoleInput, ...func(*iam.Options)) (*iam.GetRoleOutput, error)
	ListGroupsForUser(context.Context, *iam.ListGroupsForUserInput, ...func(*iam.Options)) (*iam.ListGroupsForUserOutput, error)
	ListAttachedUserPolicies(context.Context, *iam.ListAttachedUserPoliciesInput, ...func(*iam.Options)) (*iam.ListAttachedUserPoliciesOutput, error)
	ListAttachedRolePolicies(context.Context, *iam.ListAttachedRolePoliciesInput, ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error)
	ListAttachedGroupPolicies(context.Context, *iam.ListAttachedGroupPoliciesInput, ...func(*iam.Options)) (*iam.ListAttachedGroupPoliciesOutput, error)
	ListUserPolicies(context.Context, *iam.ListUserPoliciesInput, ...func(*iam.Options)) (*iam.ListUserPoliciesOutput, error)
	ListRolePolicies(context.Context, *iam.ListRolePoliciesInput, ...func(*iam.Options)) (*iam.ListRolePoliciesOutput, error)
	ListGroupPolicies(context.Context, *iam.ListGroupPoliciesInput, ...func(*iam.Options)) (*iam.ListGroupPoliciesOutput, error)
	GetUserPolicy(context.Context, *iam.GetUserPolicyInput, ...func(*iam.Options)) (*iam.GetUserPolicyOutput, error)
	GetRolePolicy(context.Context, *iam.GetRolePolicyInput, ...func(*iam.Options)) (*iam.GetRolePolicyOutput, error)
	GetGroupPolicy(context.Context, *iam.GetGroupPolicyInput, ...func(*iam.Options)) (*iam.GetGroupPolicyOutput, error)
	GetPolicy(context.Context, *iam.GetPolicyInput, ...func(*iam.Options)) (*iam.GetPolicyOutput, error)
	GetPolicyVersion(context.Context, *iam.GetPolicyVersionInput, ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error)
}

// stsClient is the part of the STS client the adapter uses.
type stsClient interface {
	GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

// sdk implements API with the AWS SDK.
type sdk struct {
	iam   iamClient
	sts   stsClient
	creds awssdk.CredentialsProvider
}

var _ API = (*sdk)(nil)

// LoadSDK returns an API that uses the credentials the AWS SDK finds on the
// host the way the AWS CLI does: the environment variables, the shared
// credentials and config files (the profile, or the default one when profile
// is empty), and the instance or container credentials.
//
// Finding credentials can itself call AWS: a profile that names a role to
// assume calls sts:AssumeRole, and single sign-on profiles call the SSO
// service. That is how the user's own tools get the same credentials, and
// the Collector adds nothing to it. It makes no other call that is not a
// read.
func LoadSDK(ctx context.Context, profile string) (API, error) {
	opts := []func(*config.LoadOptions) error{}
	if profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(profile))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("loading the AWS configuration: %w", err)
	}
	if cfg.Region == "" {
		// IAM is global, and STS answers in any region.
		cfg.Region = "us-east-1"
	}
	return NewSDK(cfg), nil
}

// NewSDK returns an API that uses cfg.
func NewSDK(cfg awssdk.Config) API {
	return &sdk{iam: iam.NewFromConfig(cfg), sts: sts.NewFromConfig(cfg), creds: cfg.Credentials}
}

// convert turns an error from the SDK into an *Error when AWS answered.
func convert(err error) error {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		return &Error{Code: ae.ErrorCode(), Message: ae.ErrorMessage()}
	}
	return err
}

// AccessKeyID implements API. It reads the credentials the SDK already
// resolved, and returns only the access key ID: the secret access key and the
// session token never leave this function.
func (s *sdk) AccessKeyID(ctx context.Context) (string, error) {
	if s.creds == nil {
		return "", errors.New("no credentials were found")
	}
	creds, err := s.creds.Retrieve(ctx)
	if err != nil {
		return "", err
	}
	return creds.AccessKeyID, nil
}

// GetCallerIdentity implements API.
func (s *sdk) GetCallerIdentity(ctx context.Context) (CallerIdentity, error) {
	out, err := s.sts.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return CallerIdentity{}, convert(err)
	}
	return CallerIdentity{Account: awssdk.ToString(out.Account), ARN: awssdk.ToString(out.Arn)}, nil
}

// GetRole implements API.
func (s *sdk) GetRole(ctx context.Context, name string) (string, error) {
	out, err := s.iam.GetRole(ctx, &iam.GetRoleInput{RoleName: &name})
	if err != nil {
		return "", convert(err)
	}
	if out.Role == nil {
		return "", errors.New("AWS returned no role")
	}
	return awssdk.ToString(out.Role.Arn), nil
}

// ListGroupsForUser implements API.
func (s *sdk) ListGroupsForUser(ctx context.Context, user string) ([]IAMGroup, error) {
	var out []IAMGroup
	p := iam.NewListGroupsForUserPaginator(s.iam, &iam.ListGroupsForUserInput{UserName: &user})
	for page := 0; page < maxPages && p.HasMorePages(); page++ {
		r, err := p.NextPage(ctx)
		if err != nil {
			return nil, convert(err)
		}
		for _, g := range r.Groups {
			out = append(out, IAMGroup{Name: awssdk.ToString(g.GroupName), ARN: awssdk.ToString(g.Arn)})
		}
	}
	return out, nil
}

// ListAttachedPolicies implements API.
func (s *sdk) ListAttachedPolicies(ctx context.Context, kind PrincipalKind, name string) ([]AttachedPolicy, error) {
	var out []AttachedPolicy
	add := func(ps []iamtypes.AttachedPolicy) {
		for _, p := range ps {
			out = append(out, AttachedPolicy{Name: awssdk.ToString(p.PolicyName), ARN: awssdk.ToString(p.PolicyArn)})
		}
	}
	switch kind {
	case User:
		p := iam.NewListAttachedUserPoliciesPaginator(s.iam, &iam.ListAttachedUserPoliciesInput{UserName: &name})
		for page := 0; page < maxPages && p.HasMorePages(); page++ {
			r, err := p.NextPage(ctx)
			if err != nil {
				return nil, convert(err)
			}
			add(r.AttachedPolicies)
		}
	case Role:
		p := iam.NewListAttachedRolePoliciesPaginator(s.iam, &iam.ListAttachedRolePoliciesInput{RoleName: &name})
		for page := 0; page < maxPages && p.HasMorePages(); page++ {
			r, err := p.NextPage(ctx)
			if err != nil {
				return nil, convert(err)
			}
			add(r.AttachedPolicies)
		}
	case Group:
		p := iam.NewListAttachedGroupPoliciesPaginator(s.iam, &iam.ListAttachedGroupPoliciesInput{GroupName: &name})
		for page := 0; page < maxPages && p.HasMorePages(); page++ {
			r, err := p.NextPage(ctx)
			if err != nil {
				return nil, convert(err)
			}
			add(r.AttachedPolicies)
		}
	default:
		return nil, fmt.Errorf("unknown principal kind %q", kind)
	}
	return out, nil
}

// ListInlinePolicyNames implements API.
func (s *sdk) ListInlinePolicyNames(ctx context.Context, kind PrincipalKind, name string) ([]string, error) {
	var out []string
	switch kind {
	case User:
		p := iam.NewListUserPoliciesPaginator(s.iam, &iam.ListUserPoliciesInput{UserName: &name})
		for page := 0; page < maxPages && p.HasMorePages(); page++ {
			r, err := p.NextPage(ctx)
			if err != nil {
				return nil, convert(err)
			}
			out = append(out, r.PolicyNames...)
		}
	case Role:
		p := iam.NewListRolePoliciesPaginator(s.iam, &iam.ListRolePoliciesInput{RoleName: &name})
		for page := 0; page < maxPages && p.HasMorePages(); page++ {
			r, err := p.NextPage(ctx)
			if err != nil {
				return nil, convert(err)
			}
			out = append(out, r.PolicyNames...)
		}
	case Group:
		p := iam.NewListGroupPoliciesPaginator(s.iam, &iam.ListGroupPoliciesInput{GroupName: &name})
		for page := 0; page < maxPages && p.HasMorePages(); page++ {
			r, err := p.NextPage(ctx)
			if err != nil {
				return nil, convert(err)
			}
			out = append(out, r.PolicyNames...)
		}
	default:
		return nil, fmt.Errorf("unknown principal kind %q", kind)
	}
	return out, nil
}

// GetInlinePolicy implements API.
func (s *sdk) GetInlinePolicy(ctx context.Context, kind PrincipalKind, name, policy string) (string, error) {
	var doc *string
	switch kind {
	case User:
		out, err := s.iam.GetUserPolicy(ctx, &iam.GetUserPolicyInput{UserName: &name, PolicyName: &policy})
		if err != nil {
			return "", convert(err)
		}
		doc = out.PolicyDocument
	case Role:
		out, err := s.iam.GetRolePolicy(ctx, &iam.GetRolePolicyInput{RoleName: &name, PolicyName: &policy})
		if err != nil {
			return "", convert(err)
		}
		doc = out.PolicyDocument
	case Group:
		out, err := s.iam.GetGroupPolicy(ctx, &iam.GetGroupPolicyInput{GroupName: &name, PolicyName: &policy})
		if err != nil {
			return "", convert(err)
		}
		doc = out.PolicyDocument
	default:
		return "", fmt.Errorf("unknown principal kind %q", kind)
	}
	return decodeDocument(doc)
}

// GetPolicy implements API.
func (s *sdk) GetPolicy(ctx context.Context, arn string) (string, error) {
	out, err := s.iam.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: &arn})
	if err != nil {
		return "", convert(err)
	}
	if out.Policy == nil {
		return "", errors.New("AWS returned no policy")
	}
	return awssdk.ToString(out.Policy.DefaultVersionId), nil
}

// GetPolicyVersion implements API.
func (s *sdk) GetPolicyVersion(ctx context.Context, arn, versionID string) (string, error) {
	out, err := s.iam.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{PolicyArn: &arn, VersionId: &versionID})
	if err != nil {
		return "", convert(err)
	}
	if out.PolicyVersion == nil {
		return "", errors.New("AWS returned no policy version")
	}
	return decodeDocument(out.PolicyVersion.Document)
}

// decodeDocument undoes the URL encoding (RFC 3986) IAM applies to a policy
// document.
func decodeDocument(doc *string) (string, error) {
	if doc == nil {
		return "", errors.New("AWS returned no policy document")
	}
	return url.PathUnescape(*doc)
}
