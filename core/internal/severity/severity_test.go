package severity_test

import (
	"testing"

	"github.com/imRYiUK/agentguard/core/internal/manifest"
	"github.com/imRYiUK/agentguard/core/internal/severity"
)

func TestOfCombinesImpactWithResourceSensitivity(t *testing.T) {
	tests := []struct {
		impact, sensitivity, want string
	}{
		// Impact weights: Read Data 1, Modify Data 2, Destroy Data 3,
		// Exfiltrate 3, Modify Identity 3, Execute Code 4, Escalate
		// Privilege 4. Sensitivity weights: low 1 .. critical 4. The product
		// is banded: 1-2 low, 3-4 medium, 6-8 high, 9-16 critical.
		{"Read Data", "low", "low"},
		{"Read Data", "critical", "medium"},
		{"Modify Data", "medium", "medium"},
		{"Destroy Data", "low", "medium"},
		{"Destroy Data", "high", "critical"},
		{"Destroy Data", "critical", "critical"},
		{"Modify Data", "critical", "high"},
		{"Execute Code", "low", "medium"},
		{"Escalate Privilege", "medium", "high"},
		{"Escalate Privilege", "critical", "critical"},
		{"Exfiltrate", "high", "critical"},
		{"Modify Identity", "medium", "high"},
		// Anything unknown stays unknown: AgentGuard never guesses.
		{"unknown", "critical", "unknown"},
		{"Destroy Data", "unknown", "unknown"},
		{"unknown", "unknown", "unknown"},
	}
	for _, tc := range tests {
		if got := severity.Of(tc.impact, tc.sensitivity); got != tc.want {
			t.Errorf("Of(%q, %q) = %q, want %q", tc.impact, tc.sensitivity, got, tc.want)
		}
	}
}

func TestSensitivityOfResourceFromLabels(t *testing.T) {
	labels := []manifest.ResourceSensitivity{
		{Resource: "arn:aws:s3:::prod-*", Sensitivity: "critical"},
		{Resource: "arn:aws:s3:::logs-*", Sensitivity: "low"},
		{Resource: "arn:aws:s3:::dev-?", Sensitivity: "medium"},
	}
	tests := []struct {
		name, resource, want string
	}{
		{"an exact resource under a label's pattern", "arn:aws:s3:::prod-billing", "critical"},
		{"the same pattern", "arn:aws:s3:::prod-*", "critical"},
		{"a narrower pattern", "arn:aws:s3:::prod-billing/*", "critical"},
		{"a resource no label applies to", "arn:aws:s3:::staging-x", "unknown"},
		{"the label's own wildcard", "arn:aws:s3:::dev-1", "medium"},
		{"a ? that cannot match a longer name", "arn:aws:s3:::dev-12", "unknown"},
		{"a wider pattern reaches every label, so the highest wins", "*", "critical"},
		{"a wider pattern within one service", "arn:aws:s3:::*", "critical"},
		{"a pattern that reaches only a low label", "arn:aws:s3:::logs-2026", "low"},
		{"another service", "arn:aws:iam::123456789012:role/x", "unknown"},
		{"stars on both sides", "arn:*:s3:::*-billing", "critical"},
		{"a star that must match something in the middle", "arn:aws:s3:::p*d-x", "critical"},
		{"a prefix that rules the label out", "arn:aws:s3:::pro", "unknown"},
	}
	r := severity.NewResolver(labels)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := r.Sensitivity(tc.resource)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("Sensitivity(%q) = %q, want %q", tc.resource, got, tc.want)
			}
		})
	}
}

func TestSensitivityWithoutLabelsIsUnknown(t *testing.T) {
	got, err := severity.NewResolver(nil).Sensitivity("*")
	if err != nil || got != "unknown" {
		t.Errorf("Sensitivity with no labels = %q, %v; want unknown", got, err)
	}
}

func TestSensitivityMatchingIsCaseSensitiveLikeARNs(t *testing.T) {
	r := severity.NewResolver([]manifest.ResourceSensitivity{{Resource: "arn:aws:s3:::Prod-*", Sensitivity: "high"}})
	got, _ := r.Sensitivity("arn:aws:s3:::prod-a")
	if got != "unknown" {
		t.Errorf("S3 bucket names are case-sensitive; got %q, want unknown", got)
	}
}

func TestSensitivityStopsWhenItRunsOutOfWork(t *testing.T) {
	long := make([]byte, 2000)
	for i := range long {
		long[i] = '*'
	}
	r := severity.NewResolver([]manifest.ResourceSensitivity{{Resource: string(long) + "x", Sensitivity: "high"}})
	r.SetBudget(1000)
	if _, err := r.Sensitivity(string(long) + "y"); err == nil {
		t.Error("want an error once the work budget is spent, got none")
	}
}
