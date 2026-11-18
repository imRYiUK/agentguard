package report_test

import (
	"testing"

	analysisv1 "github.com/imRYiUK/agentguard/proto/gen/go/agentguard/analysis/v1"

	"github.com/imRYiUK/agentguard/cli/internal/report"
)

func resultWith(severities ...analysisv1.Severity) *analysisv1.AnalysisResult {
	r := &analysisv1.AnalysisResult{}
	for _, s := range severities {
		r.ReachPaths = append(r.ReachPaths, &analysisv1.ReachPath{Severity: s})
	}
	return r
}

func TestParseThreshold(t *testing.T) {
	for name, want := range map[string]analysisv1.Severity{
		"low":      analysisv1.Severity_SEVERITY_LOW,
		"medium":   analysisv1.Severity_SEVERITY_MEDIUM,
		"high":     analysisv1.Severity_SEVERITY_HIGH,
		"critical": analysisv1.Severity_SEVERITY_CRITICAL,
	} {
		got, err := report.ParseThreshold(name)
		if err != nil || got != want {
			t.Errorf("ParseThreshold(%q) = %v, %v; want %v", name, got, err, want)
		}
	}
	for _, bad := range []string{"", "unknown", "urgent", "HIGH", "SEVERITY_HIGH"} {
		if _, err := report.ParseThreshold(bad); err == nil {
			t.Errorf("ParseThreshold(%q) must fail", bad)
		}
	}
}

func TestMeetsThreshold(t *testing.T) {
	const (
		unknown  = analysisv1.Severity_SEVERITY_UNKNOWN
		low      = analysisv1.Severity_SEVERITY_LOW
		medium   = analysisv1.Severity_SEVERITY_MEDIUM
		high     = analysisv1.Severity_SEVERITY_HIGH
		critical = analysisv1.Severity_SEVERITY_CRITICAL
	)
	tests := []struct {
		name      string
		result    *analysisv1.AnalysisResult
		threshold analysisv1.Severity
		want      bool
	}{
		{"no Reach Paths", resultWith(), low, false},
		{"a path at the threshold meets it", resultWith(high), high, true},
		{"a path above the threshold meets it", resultWith(critical), medium, true},
		{"a path below the threshold does not", resultWith(medium), high, false},
		{"one path among many is enough", resultWith(low, unknown, critical, low), critical, true},
		{"every path below the threshold", resultWith(low, medium, high), critical, false},
		{"unknown severity never meets a threshold", resultWith(unknown, unknown), low, false},
	}
	for _, tt := range tests {
		if got := report.MeetsThreshold(tt.result, tt.threshold); got != tt.want {
			t.Errorf("%s: got %v, want %v", tt.name, got, tt.want)
		}
	}
}
