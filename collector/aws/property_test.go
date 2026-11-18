package aws_test

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/imRYiUK/agentguard/collector/aws"
	"github.com/imRYiUK/agentguard/collector/awstest"
)

// The planted-secrets property: for any generated account, whatever secrets
// are planted in it, the Snapshot the Collector writes contains none of
// them. Each iteration builds a random account, plants secrets where the
// real ones live (the credentials) and where a hostile or careless account
// might put them (error messages, error codes, policy text, names), collects
// it, and searches the Snapshot's JSON for every planted value.

const iterations = 500

var secretAlphabets = []string{
	"abcdefghijklmnopqrstuvwxyz",
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/+=",
	"abcdef0123456789",
	"pässwörd-секрет-秘密-🔑",
	`ab"\/ :;#[]=`,
}

// plant returns a random secret of at least 16 characters, so that it could
// not turn up in a Snapshot by chance.
func plant(r *rand.Rand) string {
	alphabet := []rune(secretAlphabets[r.IntN(len(secretAlphabets))])
	n := 16 + r.IntN(40)
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteRune(alphabet[r.IntN(len(alphabet))])
	}
	return strings.TrimSpace(b.String()) + "Zq"
}

func pick[T any](r *rand.Rand, xs ...T) T { return xs[r.IntN(len(xs))] }

// quote returns the JSON string literal of s, which is how s would appear in
// a document.
func quote(s string) json.RawMessage {
	b, _ := json.Marshal(s)
	return b
}

// randomAccount builds a fake account with secrets planted in every
// position, and returns it with the planted values.
func randomAccount(r *rand.Rand) (awstest.Account, []string) {
	var planted []string
	next := func() string {
		s := plant(r)
		planted = append(planted, s)
		return s
	}
	// A fake document: ordinary statements, with planted text in free-text
	// positions that a policy may legitimately hold, such as a Sid. Those
	// are not secrets in the sense AgentGuard detects, so the Collector may
	// record them: only the values the Collector was never given are checked
	// for, and a document it does record is checked with the planted text
	// left out.
	doc := func() json.RawMessage {
		return json.RawMessage(fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":%s,"Resource":%s}]}`,
			pick(r, `"s3:*"`, `["s3:Get*","iam:PassRole"]`, `"*"`),
			pick(r, `"*"`, `"arn:aws:s3:::bucket/*"`)))
	}

	acct := awstest.Account{
		AccessKeyID:     pick(r, "AKIA", "ASIA") + strings.ToUpper(plantBase32(r, 16)),
		SecretAccessKey: next(),
		SessionToken:    next(),
		Managed:         map[string]awstest.ManagedPolicy{},
		Failures:        map[string]awstest.Failure{},
		Users:           map[string]awstest.Principal{},
		Roles:           map[string]awstest.Principal{},
		Groups:          map[string]awstest.Principal{},
	}
	planted = append(planted, acct.AccessKeyID)
	principal := func(kindName string) awstest.Principal {
		p := awstest.Principal{Inline: map[string]json.RawMessage{}}
		for i := 0; i < r.IntN(3); i++ {
			arn := fmt.Sprintf("arn:aws:iam::123456789012:policy/%s-%d", kindName, i)
			acct.Managed[arn] = awstest.ManagedPolicy{DefaultVersion: "v1", Versions: map[string]json.RawMessage{"v1": doc()}}
			p.Attached = append(p.Attached, aws.AttachedPolicy{Name: fmt.Sprintf("%s-%d", kindName, i), ARN: arn})
		}
		for i := 0; i < r.IntN(3); i++ {
			p.Inline[fmt.Sprintf("inline-%d", i)] = doc()
		}
		return p
	}
	// A message or a code that carries a secret, on a call that fails.
	fail := func(call string) {
		acct.Failures[call] = awstest.Failure{
			Code:    pick(r, "AccessDenied", "Throttling", next()+"!", "Bad "+next()),
			Message: "request " + next() + " failed for " + next(),
		}
	}

	switch r.IntN(2) {
	case 0:
		acct.Caller = aws.CallerIdentity{Account: "123456789012", ARN: "arn:aws:iam::123456789012:user/deploy"}
		u := principal("user")
		for i := 0; i < r.IntN(3); i++ {
			name := fmt.Sprintf("group%d", i)
			u.Groups = append(u.Groups, name)
			acct.Groups[name] = principal("group")
			g := acct.Groups[name]
			g.ARN = "arn:aws:iam::123456789012:group/" + name
			acct.Groups[name] = g
		}
		acct.Users["deploy"] = u
		for _, call := range []string{"iam:ListAttachedUserPolicies", "iam:ListUserPolicies", "iam:ListGroupsForUser", "iam:GetUserPolicy", "iam:ListAttachedGroupPolicies"} {
			if r.IntN(4) == 0 {
				fail(call)
			}
		}
	default:
		acct.Caller = aws.CallerIdentity{Account: "123456789012", ARN: "arn:aws:sts::123456789012:assumed-role/ops/" + "s"}
		role := principal("role")
		role.ARN = "arn:aws:iam::123456789012:role/ops"
		acct.Roles["ops"] = role
		for _, call := range []string{"iam:GetRole", "iam:ListAttachedRolePolicies", "iam:ListRolePolicies", "iam:GetRolePolicy", "iam:GetPolicy", "iam:GetPolicyVersion"} {
			if r.IntN(4) == 0 {
				fail(call)
			}
		}
	}
	if r.IntN(4) == 0 {
		acct.KeyUnavailable = true
	}
	// A policy document that holds a planted secret in a position AgentGuard
	// would reject must be left out of the Snapshot, so the secret never
	// reaches it.
	if r.IntN(2) == 0 {
		leak := "AKIA" + strings.ToUpper(plantBase32(r, 16))
		planted = append(planted, leak)
		bad := json.RawMessage(fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Sid":%s,"Effect":"Allow","Action":"*","Resource":"*"}]}`, quote(leak)))
		if u, ok := acct.Users["deploy"]; ok {
			u.Inline["leaky"] = bad
		} else {
			acct.Roles["ops"].Inline["leaky"] = bad
		}
	}
	return acct, planted
}

func plantBase32(r *rand.Rand, n int) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[r.IntN(len(alphabet))]
	}
	return string(b)
}

func TestSnapshotNeverContainsAPlantedSecret(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for i := 0; i < iterations; i++ {
		acct, planted := randomAccount(r)
		snap, err := aws.Collect(context.Background(), awstest.New(acct), testOptions)
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		out, err := aws.MarshalJSON(snap)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range planted {
			quoted, _ := json.Marshal(secret)
			if strings.Contains(string(out), secret) || strings.Contains(string(out), string(quoted[1:len(quoted)-1])) {
				t.Fatalf("iteration %d: the Snapshot contains the planted secret %q:\n%s", i, secret, out)
			}
		}
	}
}
