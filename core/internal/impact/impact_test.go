package impact_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/imRYiUK/agentguard/core/internal/impact"
)

func TestDefaultTableIsWellFormed(t *testing.T) {
	table, err := impact.Default()
	if err != nil {
		t.Fatal(err)
	}
	if table.Version == "" {
		t.Error("the table has no version")
	}
	seen := map[string]bool{}
	for i, m := range table.Mappings {
		if seen[strings.ToLower(m.Action)] {
			t.Errorf("mappings[%d]: duplicate action %q", i, m.Action)
		}
		seen[strings.ToLower(m.Action)] = true
		if !strings.Contains(m.Action, ":") {
			t.Errorf("mappings[%d]: action %q is not of the form service:Action", i, m.Action)
		}
		if len(m.Impacts) == 0 {
			t.Errorf("mappings[%d] (%s): names no Impact", i, m.Action)
		}
		if strings.TrimSpace(m.Rationale) == "" {
			t.Errorf("mappings[%d] (%s): has no rationale", i, m.Action)
		}
	}
}

// The first S3 and IAM actions the table must cover. The expected Impacts are
// written out by hand, independently of the table.
func TestDefaultTableCoversTheFirstS3AndIAMActions(t *testing.T) {
	table, err := impact.Default()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"s3:GetObject":         {"Read Data"},
		"s3:PutObject":         {"Modify Data"},
		"s3:DeleteObject":      {"Destroy Data"},
		"s3:DeleteBucket":      {"Destroy Data"},
		"s3:PutBucketPolicy":   {"Exfiltrate"},
		"iam:PassRole":         {"Escalate Privilege"},
		"iam:CreateUser":       {"Modify Identity"},
		"iam:AttachUserPolicy": {"Escalate Privilege", "Modify Identity"},
	}
	got := map[string][]string{}
	for _, m := range table.Mappings {
		got[m.Action] = m.Impacts
	}
	for action, impacts := range want {
		if !slices.Equal(got[action], impacts) {
			t.Errorf("%s: Impacts = %v, want %v", action, got[action], impacts)
		}
	}
}
