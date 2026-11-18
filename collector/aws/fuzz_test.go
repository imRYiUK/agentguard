package aws_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/imRYiUK/agentguard/collector/aws"
	"github.com/imRYiUK/agentguard/collector/awstest"
)

// FuzzCollectPolicyDocument feeds the Collector arbitrary policy document
// text, which is untrusted input from the account. It must never panic and
// must write valid JSON. It may leave the document out, as a Blind Spot, but
// it must not fail the collection.
func FuzzCollectPolicyDocument(f *testing.F) {
	f.Add(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`)
	f.Add(`{"Sid":"AKIAIOSFODNN7EXAMPLE"}`)
	f.Add(`{"Sid":"AKIAIOSFODNN7EXAMPLE"}`)
	f.Add(`{"password":"x"}`)
	f.Add(strings.Repeat("[", 40) + strings.Repeat("]", 40))
	f.Add(`null`)
	f.Add(`{"a":`)
	f.Add("\x00\xff")
	f.Fuzz(func(t *testing.T, doc string) {
		fake := awstest.New(awstest.Account{
			AccessKeyID: "AKIAIOSFODNN7EXAMPLE",
			Caller:      aws.CallerIdentity{Account: "123456789012", ARN: "arn:aws:iam::123456789012:user/deploy"},
			Users: map[string]awstest.Principal{"deploy": {
				Inline: map[string]json.RawMessage{"fuzzed": json.RawMessage(doc)},
			}},
		})
		snap, err := aws.Collect(context.Background(), fake, testOptions)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		out, err := aws.MarshalJSON(snap)
		if err != nil {
			t.Fatal(err)
		}
		if !json.Valid(out) {
			t.Fatalf("invalid JSON:\n%s", out)
		}
	})
}
