package aws_test

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/imRYiUK/agentguard/collector/aws"
	"github.com/imRYiUK/agentguard/collector/awstest"
	"github.com/imRYiUK/agentguard/collector/host"
	"github.com/imRYiUK/agentguard/collector/hosttest"
	"github.com/imRYiUK/agentguard/collector/linux"
)

// readOnlyCall is every AWS call the Collector may make.
func readOnlyCall(call string) bool {
	return call == "sts:GetCallerIdentity" ||
		strings.HasPrefix(call, "iam:Get") || strings.HasPrefix(call, "iam:List")
}

// The Collector only reads: over every fake account, each call it makes is a
// Get or a List.
func TestCollectMakesOnlyReadOnlyCalls(t *testing.T) {
	dirs, err := filepath.Glob(filepath.Join(accountsDir, "*", "account.json"))
	if err != nil || len(dirs) == 0 {
		t.Fatalf("no fake accounts found: %v", err)
	}
	for _, file := range dirs {
		fake, err := awstest.Load(file)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := aws.Collect(context.Background(), fake, testOptions); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		calls := fake.Calls()
		if len(calls) == 0 {
			t.Errorf("%s: the Collector made no calls", file)
		}
		for _, call := range calls {
			if !readOnlyCall(call) {
				t.Errorf("%s: the Collector made %s, which is not read-only", file, call)
			}
		}
	}
}

// The interface is the guarantee: it has no method that could write. A method
// added to it must be named like a read, so adding a write is a change a
// reviewer, and this test, will see.
func TestAPIHasOnlyReadMethods(t *testing.T) {
	typ := reflect.TypeOf((*aws.API)(nil)).Elem()
	for i := 0; i < typ.NumMethod(); i++ {
		name := typ.Method(i).Name
		if name != "AccessKeyID" && !strings.HasPrefix(name, "Get") && !strings.HasPrefix(name, "List") {
			t.Errorf("aws.API has a method %s, which is not a Get or a List", name)
		}
	}
}

// An account the Collector cannot identify gives no Snapshot, and the error
// says why without repeating AWS's message, which could echo a secret.
func TestCollectFailsWhenTheCredentialsDoNotResolve(t *testing.T) {
	const secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	fake := awstest.New(awstest.Account{
		AccessKeyID: "AKIAIOSFODNN7EXAMPLE",
		Failures: map[string]awstest.Failure{
			"sts:GetCallerIdentity": {Code: "ExpiredToken", Message: "the token " + secret + " is expired"},
		},
	})
	snap, err := aws.Collect(context.Background(), fake, testOptions)
	if err == nil {
		t.Fatalf("want an error, got the Snapshot %v", snap)
	}
	if !strings.Contains(err.Error(), "ExpiredToken") {
		t.Errorf("the error does not give AWS's error code: %v", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("the error repeats AWS's message: %v", err)
	}
}

func TestCollectRejectsIdentitiesThatCannotBeRecorded(t *testing.T) {
	for name, caller := range map[string]aws.CallerIdentity{
		"account is not 12 digits": {Account: "12345", ARN: "arn:aws:iam::12345:user/x"},
		"caller is not an ARN":     {Account: "123456789012", ARN: "deploy"},
	} {
		t.Run(name, func(t *testing.T) {
			fake := awstest.New(awstest.Account{AccessKeyID: "AKIAIOSFODNN7EXAMPLE", Caller: caller})
			if _, err := aws.Collect(context.Background(), fake, testOptions); err == nil {
				t.Error("want an error")
			}
		})
	}
}

func TestCollectNeedsItsOptions(t *testing.T) {
	fake := awstest.New(awstest.Account{})
	for name, opts := range map[string]aws.Options{
		"version":     {Now: testOptions.Now, SnapshotID: "x"},
		"snapshot ID": {Version: "1", Now: testOptions.Now},
		"time":        {Version: "1", SnapshotID: "x"},
	} {
		if _, err := aws.Collect(context.Background(), fake, opts); err == nil {
			t.Errorf("a missing %s was accepted", name)
		}
	}
}

// Losing the access key ID costs the link to a credential file, which is a
// Blind Spot, not the Snapshot.
func TestCollectRecordsABlindSpotWhenTheAccessKeyIDCannotBeRead(t *testing.T) {
	fake := awstest.New(awstest.Account{
		KeyUnavailable:  true,
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		Caller:          aws.CallerIdentity{Account: "123456789012", ARN: "arn:aws:iam::123456789012:user/deploy"},
		Users:           map[string]awstest.Principal{"deploy": {}},
	})
	snap, err := aws.Collect(context.Background(), fake, testOptions)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := aws.MarshalJSON(snap)
	if strings.Contains(string(out), "wJalr") {
		t.Errorf("the Snapshot contains the secret:\n%s", out)
	}
	if len(snap.GetAws().GetIdentities()[0].GetAccessKeyIdFingerprints()) != 0 {
		t.Error("an Identity with no readable access key ID has a fingerprint")
	}
	found := false
	for _, b := range snap.GetBlindSpots() {
		found = found || strings.Contains(b.GetAttempted(), "access key ID")
	}
	if !found {
		t.Errorf("no Blind Spot names the access key ID: %v", snap.GetBlindSpots())
	}
}

func TestCollectNamesTheUncollectedPolicyTypes(t *testing.T) {
	snap, err := aws.Collect(context.Background(), loadAccount(t, "user-in-group"), testOptions)
	if err != nil {
		t.Fatal(err)
	}
	var all strings.Builder
	for _, b := range snap.GetBlindSpots() {
		all.WriteString(b.GetAttempted() + "\n")
	}
	for _, want := range []string{"service control policies", "resource control policies", "permission boundaries", "session policies", "resource-based policies"} {
		if !strings.Contains(all.String(), want) {
			t.Errorf("no Blind Spot for %s:\n%s", want, all.String())
		}
	}
}

// A Linux Snapshot links a credential profile to an Identity by the
// fingerprint of the access key ID. Both Collectors must make it the same
// way, or the link breaks without any error.
func TestAccessKeyFingerprintMatchesTheLinuxCollector(t *testing.T) {
	const keyID = "AKIAIOSFODNN7EXAMPLE"
	fakeHost := &hosttest.Host{
		Proc: host.Process{UID: 1001, GID: 1001},
		Entries: map[string]hosttest.Entry{
			"/etc/machine-id":               {Lines: []string{"e8c913f01b6f9ef3d7f19c3cef1cc390"}},
			"/etc/passwd":                   {Lines: []string{"deploy:x:1001:1001::/home/deploy:/bin/bash"}},
			"/etc/group":                    {Lines: []string{"deploy:x:1001:"}},
			"/home/deploy":                  {Type: "dir", Mode: "0750", UID: 1001, GID: 1001},
			"/home/deploy/.aws":             {Type: "dir", Mode: "0700", UID: 1001, GID: 1001},
			"/home/deploy/.aws/credentials": {Mode: "0600", UID: 1001, GID: 1001, Lines: []string{"[ops]", "aws_access_key_id = " + keyID, "aws_secret_access_key = secret"}},
		},
	}
	linuxSnap, err := linux.Collect(fakeHost, linux.Options{Version: "1", Now: testOptions.Now, SnapshotID: "x"})
	if err != nil {
		t.Fatal(err)
	}
	awsSnap, err := aws.Collect(context.Background(), loadAccount(t, "user-in-group"), testOptions)
	if err != nil {
		t.Fatal(err)
	}
	want := linuxSnap.GetLinux().GetCredentialFiles()[0].GetAwsProfiles()[0].GetAccessKeyIdFingerprint()
	got := awsSnap.GetAws().GetIdentities()[0].GetAccessKeyIdFingerprints()
	if want == "" || len(got) != 1 || got[0] != want {
		t.Errorf("fingerprints differ: the Linux Collector wrote %q, the AWS Collector %v", want, got)
	}
}

// An AWS error is recorded as its code. A message, which AWS writes and may
// echo anything, is not.
func TestBlindSpotNeverRepeatsAnErrorMessage(t *testing.T) {
	const secret = "pässwörd-SECRET-0123456789"
	acct := awstest.Account{
		AccessKeyID: "AKIAIOSFODNN7EXAMPLE",
		Caller:      aws.CallerIdentity{Account: "123456789012", ARN: "arn:aws:iam::123456789012:user/deploy"},
		Users:       map[string]awstest.Principal{"deploy": {}},
		Failures: map[string]awstest.Failure{
			"iam:ListAttachedUserPolicies": {Code: "AccessDenied", Message: secret},
			"iam:ListUserPolicies":         {Code: "Code With Spaces " + secret, Message: secret},
			"iam:ListGroupsForUser":        {Code: "A" + strings.Repeat("a", 100), Message: secret},
		},
	}
	snap, err := aws.Collect(context.Background(), awstest.New(acct), testOptions)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := aws.MarshalJSON(snap)
	if strings.Contains(string(out), "SECRET") {
		t.Errorf("the Snapshot repeats an error message:\n%s", out)
	}
}

// A non-AWS error, such as a network failure, is a Blind Spot without detail.
func TestBlindSpotForAnErrorThatIsNotFromAWS(t *testing.T) {
	api := &failingAPI{Fake: loadAccount(t, "user-in-group")}
	snap, err := aws.Collect(context.Background(), api, testOptions)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range snap.GetBlindSpots() {
		if strings.Contains(b.GetAttempted(), "iam:ListGroupsForUser") {
			if b.GetReason() != "the call failed" {
				t.Errorf("reason = %q", b.GetReason())
			}
			return
		}
	}
	t.Error("the failed call is not a Blind Spot")
}

type failingAPI struct{ *awstest.Fake }

func (f *failingAPI) ListGroupsForUser(context.Context, string) ([]aws.IAMGroup, error) {
	return nil, errors.New("dial tcp: lookup iam.amazonaws.com: AKIAIOSFODNN7EXAMPLE secret")
}

func loadAccount(t *testing.T, name string) *awstest.Fake {
	t.Helper()
	fake, err := awstest.Load(filepath.Join(accountsDir, name, "account.json"))
	if err != nil {
		t.Fatal(err)
	}
	return fake
}
