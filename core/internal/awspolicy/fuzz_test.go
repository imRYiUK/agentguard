package awspolicy_test

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/imRYiUK/agentguard/core/internal/awspolicy"
	"github.com/imRYiUK/agentguard/core/internal/fuzzutil"
	"github.com/imRYiUK/agentguard/core/internal/limits"
)

// FuzzGrants checks that reading an IAM policy document never panics and
// always enforces the limits, whatever the document.
func FuzzGrants(f *testing.F) {
	f.Add([]byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`))
	f.Add([]byte(`{"Statement":{"Effect":"Allow","Action":["a:b","c:d"],"Resource":["x","y"]}}`))
	f.Add([]byte(`{"Statement":[{"Effect":"Deny","NotAction":"s3:*","NotResource":"*","Condition":{"Bool":{"k":"v"}}}]}`))
	f.Add([]byte(`{"Statement":"nope"}`))
	f.Add([]byte(`{"Statement":[{"Effect":"Allow","Action":1,"Resource":null}]}`))
	f.Add([]byte(`{"Statement":[{"Condition":{"a":{"b":` + strings.Repeat("[", 20) + strings.Repeat("]", 20) + `}}}]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"Statement":[{"Sid":"` + strings.Repeat("a ", limits.MaxPolicyDocumentBytes) + `"}]}`))

	f.Fuzz(func(t *testing.T, content []byte) {
		var doc structpb.Struct
		if err := protojson.Unmarshal(content, &doc); err != nil {
			t.Skip("not a JSON object")
		}
		_, err := awspolicy.Grants(&doc)
		if proto.Size(&doc) > limits.MaxPolicyDocumentBytes && err == nil {
			t.Fatalf("accepted a document of %d bytes; the limit is %d", proto.Size(&doc), limits.MaxPolicyDocumentBytes)
		}
		if depth, ok := fuzzutil.JSONDepth(content); ok && depth > limits.MaxPolicyDepth && err == nil {
			t.Fatalf("accepted a document nested %d levels; the limit is %d", depth, limits.MaxPolicyDepth)
		}
	})
}
