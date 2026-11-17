package snapshot_test

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/imRYiUK/agentguard/core/internal/fuzzutil"
	"github.com/imRYiUK/agentguard/core/internal/limits"
	"github.com/imRYiUK/agentguard/core/internal/snapshot"
)

// plantedSecrets are fake secret values. A Snapshot that Parse accepts must
// never carry any of them, however they were written in the input.
var plantedSecrets = []string{
	"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	"AKIAIOSFODNN7EXAMPLE",
	"IQoJb3JpZ2luX2VjEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE",
	"-----BEGIN OPENSSH PRIVATE KEY-----",
	"ghp_abcdefghijklmnopqrstuvwxyz0123456789",
	"xoxb-123456789012-abcdefghijklmnop",
	"sk-ant-api03-abcdefghijklmnopqrstuvwxyz",
}

// FuzzParse checks that Parse never panics, always enforces its limits, and
// never accepts a Snapshot that carries a planted secret.
func FuzzParse(f *testing.F) {
	f.Add(fuzzutil.Seed(f, "snapshots/linux.json"))
	f.Add(fuzzutil.Seed(f, "snapshots/aws.json"))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"schemaVersion":"1","collectedBy":"` + plantedSecrets[0] + `"}`))
	f.Add([]byte(`{"schemaVersion":"1","collectedBy":"AKIAIOSFODNN7EXAMPLE"}`))
	f.Add([]byte(`{"x":` + strings.Repeat("[", 40) + strings.Repeat("]", 40) + `}`))
	f.Add([]byte(strings.Repeat("{", 20000)))
	f.Add([]byte(`{"x":"` + strings.Repeat("a ", limits.MaxSnapshotBytes/2) + `"}`))
	for _, s := range plantedSecrets {
		f.Add([]byte(`{"schemaVersion":"1","snapshotId":"` + strings.ReplaceAll(s, "\n", `\n`) + `"}`))
		f.Add([]byte(`{"blindSpots":[{"attempted":"x","reason":"[ops]\naws_secret_access_key = ` + s + `"}]}`))
	}

	f.Fuzz(func(t *testing.T, content []byte) {
		snap, err := snapshot.Parse("snapshot.json", content)
		if len(content) > limits.MaxSnapshotBytes && err == nil {
			t.Fatalf("accepted %d bytes; the limit is %d", len(content), limits.MaxSnapshotBytes)
		}
		if depth, ok := fuzzutil.JSONDepth(content); ok && depth > limits.MaxDepth && err == nil {
			t.Fatalf("accepted a document nested %d levels; the limit is %d", depth, limits.MaxDepth)
		}
		if err != nil {
			for _, s := range plantedSecrets {
				if strings.Contains(err.Error(), s) {
					t.Fatalf("the error echoes a secret: %v", err)
				}
			}
			return
		}
		out, err := protojson.Marshal(snap)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range plantedSecrets {
			if strings.Contains(string(out), s) || strings.Contains(string(out), strings.ReplaceAll(s, "\n", `\n`)) {
				t.Fatalf("accepted a Snapshot carrying the planted secret %q", s)
			}
		}
	})
}
