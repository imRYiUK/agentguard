// Package report turns an analysis result into what the CLI prints, and
// decides whether the result fails a Deployment Gate.
package report

import (
	"fmt"

	analysisv1 "github.com/imRYiUK/agentguard/proto/gen/go/agentguard/analysis/v1"
)

// thresholds are the severities a Deployment Gate can be set to, by the name
// the user types. SEVERITY_UNKNOWN is not among them: an unknown severity is
// not a level, it is the absence of a judgement.
var thresholds = map[string]analysisv1.Severity{
	"low":      analysisv1.Severity_SEVERITY_LOW,
	"medium":   analysisv1.Severity_SEVERITY_MEDIUM,
	"high":     analysisv1.Severity_SEVERITY_HIGH,
	"critical": analysisv1.Severity_SEVERITY_CRITICAL,
}

// ParseThreshold returns the severity named low, medium, high, or critical.
func ParseThreshold(name string) (analysisv1.Severity, error) {
	if s, ok := thresholds[name]; ok {
		return s, nil
	}
	return 0, fmt.Errorf("%q is not a severity threshold; use low, medium, high, or critical", name)
}

// MeetsThreshold reports whether any Reach Path has a severity at or above
// the threshold. A Reach Path of unknown severity never does: AgentGuard does
// not guess how much it matters, so the gate does not either.
func MeetsThreshold(result *analysisv1.AnalysisResult, threshold analysisv1.Severity) bool {
	for _, p := range result.GetReachPaths() {
		// The enum numbers the known severities in increasing order, after
		// unspecified and unknown.
		if s := p.GetSeverity(); s >= analysisv1.Severity_SEVERITY_LOW && s >= threshold {
			return true
		}
	}
	return false
}
