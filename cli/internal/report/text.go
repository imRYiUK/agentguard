package report

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	analysisv1 "github.com/imRYiUK/agentguard/proto/gen/go/agentguard/analysis/v1"
)

// Text renders an analysis result as a plain-text summary for a person at a
// terminal or reading a CI log. Reach Paths come most severe first, ties
// broken by Reach Path Fingerprint, so the same result always gives the same
// bytes, whatever order the result lists its paths in. It uses no colour and
// no terminal features, and does not modify the result.
func Text(result *analysisv1.AnalysisResult) []byte {
	var b strings.Builder
	writeInput(&b, result)

	paths := slices.Clone(result.GetReachPaths())
	slices.SortStableFunc(paths, func(x, y *analysisv1.ReachPath) int {
		return cmp.Or(
			cmp.Compare(severityRank(y.GetSeverity()), severityRank(x.GetSeverity())),
			cmp.Compare(x.GetFingerprint(), y.GetFingerprint()),
		)
	})
	b.WriteString("\n")
	if len(paths) == 0 {
		b.WriteString("No Reach Paths found.\n")
	} else {
		noun := "Reach Paths"
		if len(paths) == 1 {
			noun = "Reach Path"
		}
		fmt.Fprintf(&b, "%d %s: %s\n", len(paths), noun, severityCounts(paths))
		for i, p := range paths {
			b.WriteString("\n")
			writePath(&b, i+1, p)
		}
	}

	if findings := result.GetSecondaryFindings(); len(findings) > 0 {
		fmt.Fprintf(&b, "\nSecondary Findings: %d\n", len(findings))
		for _, f := range findings {
			fmt.Fprintf(&b, "  - %s (%s)%s\n", f.GetLabel(), f.GetAgentDeployment(), confidenceNote(f.GetConfidence(), f.GetConfidenceReason()))
			fmt.Fprintf(&b, "      evidence: %s\n", evidence(f.GetEvidence()))
		}
	}
	if spots := result.GetBlindSpots(); len(spots) > 0 {
		fmt.Fprintf(&b, "\nBlind Spots: %d\n", len(spots))
		for _, s := range spots {
			fmt.Fprintf(&b, "  - %s: could not complete %q (%s)\n", s.GetEnvironment(), s.GetAttempted(), s.GetReason())
			fmt.Fprintf(&b, "      evidence: %s\n", evidence(s.GetEvidence()))
		}
	}
	return []byte(b.String())
}

func writeInput(b *strings.Builder, result *analysisv1.AnalysisResult) {
	in := result.GetAnalysisInput()
	b.WriteString("AgentGuard analysis\n")
	if in.GetAnalyzedAt() != nil {
		fmt.Fprintf(b, "  Analyzed at %s; a Snapshot is stale after %s\n",
			in.GetAnalyzedAt().AsTime().UTC().Format(time.RFC3339), in.GetStalenessThreshold().AsDuration())
	}
	if in.GetManifestDigest() != "" {
		fmt.Fprintf(b, "  Agent Manifest %s\n", in.GetManifestDigest())
	}
	for _, s := range in.GetSnapshots() {
		stale := ""
		if s.GetStale() {
			stale = " (stale)"
		}
		fmt.Fprintf(b, "  Snapshot %s of %s, collected at %s%s\n", s.GetSnapshotId(), s.GetEnvironment(),
			s.GetCollectedAt().AsTime().UTC().Format(time.RFC3339), stale)
	}
	fmt.Fprintf(b, "  Impact mapping version %s, rules version %s\n", result.GetImpactMappingVersion(), result.GetRulesVersion())
}

func writePath(b *strings.Builder, n int, p *analysisv1.ReachPath) {
	fmt.Fprintf(b, "%d. %s  %s%s\n", n, severityName(p.GetSeverity()), p.GetAgentDeployment(),
		confidenceNote(p.GetConfidence(), ""))
	fmt.Fprintf(b, "   fingerprint %s, resource sensitivity %s\n", p.GetFingerprint(), sensitivityName(p.GetResourceSensitivity()))
	for i, l := range p.GetLinks() {
		arrow := "->"
		if i == 0 {
			arrow = "  "
		}
		origin := ""
		if l.GetKind() == analysisv1.LinkKind_LINK_KIND_IDENTITY {
			origin = " [" + originName(l.GetOrigin()) + "]"
		}
		fmt.Fprintf(b, "   %s %s: %s%s%s\n", arrow, kindName(l.GetKind()), l.GetLabel(), origin,
			confidenceNote(l.GetConfidence(), l.GetConfidenceReason()))
		fmt.Fprintf(b, "        evidence: %s\n", evidence(l.GetEvidence()))
	}
	for _, reason := range p.GetConfidenceReasons() {
		fmt.Fprintf(b, "   confidence reduced: %s\n", reason)
	}
}

func evidence(e *analysisv1.Evidence) string {
	return e.GetSource() + " " + e.GetLocation()
}

// confidenceNote is empty for high Confidence, which needs no remark.
func confidenceNote(c analysisv1.Confidence, reason string) string {
	if c != analysisv1.Confidence_CONFIDENCE_REDUCED {
		return ""
	}
	if reason == "" {
		return " (confidence: reduced)"
	}
	return " (confidence: reduced, " + reason + ")"
}

// severityRank orders severities for display: unknown, and anything the
// result does not name, rank below every known severity.
func severityRank(s analysisv1.Severity) int {
	if s >= analysisv1.Severity_SEVERITY_LOW {
		return int(s)
	}
	return 0
}

// severityCounts is the per-severity tally of a summary line, most severe
// first, with unknown last.
func severityCounts(paths []*analysisv1.ReachPath) string {
	counts := map[string]int{}
	for _, p := range paths {
		counts[severityName(p.GetSeverity())]++
	}
	var parts []string
	for _, name := range []string{"critical", "high", "medium", "low", "unknown"} {
		parts = append(parts, fmt.Sprintf("%d %s", counts[name], name))
	}
	return strings.Join(parts, ", ")
}

func severityName(s analysisv1.Severity) string {
	switch s {
	case analysisv1.Severity_SEVERITY_LOW:
		return "low"
	case analysisv1.Severity_SEVERITY_MEDIUM:
		return "medium"
	case analysisv1.Severity_SEVERITY_HIGH:
		return "high"
	case analysisv1.Severity_SEVERITY_CRITICAL:
		return "critical"
	default:
		return "unknown"
	}
}

func sensitivityName(s analysisv1.Sensitivity) string {
	switch s {
	case analysisv1.Sensitivity_SENSITIVITY_LOW:
		return "low"
	case analysisv1.Sensitivity_SENSITIVITY_MEDIUM:
		return "medium"
	case analysisv1.Sensitivity_SENSITIVITY_HIGH:
		return "high"
	case analysisv1.Sensitivity_SENSITIVITY_CRITICAL:
		return "critical"
	default:
		return "unknown"
	}
}

func originName(o analysisv1.BindingOrigin) string {
	switch o {
	case analysisv1.BindingOrigin_BINDING_ORIGIN_DECLARED:
		return "declared"
	case analysisv1.BindingOrigin_BINDING_ORIGIN_DISCOVERED:
		return "discovered"
	case analysisv1.BindingOrigin_BINDING_ORIGIN_INFERRED:
		return "inferred"
	default:
		return "origin unspecified"
	}
}

func kindName(k analysisv1.LinkKind) string {
	switch k {
	case analysisv1.LinkKind_LINK_KIND_TOOL:
		return "Tool"
	case analysisv1.LinkKind_LINK_KIND_IDENTITY:
		return "Identity"
	case analysisv1.LinkKind_LINK_KIND_IDENTITY_HOP:
		return "Identity Hop"
	case analysisv1.LinkKind_LINK_KIND_NATIVE_PERMISSION:
		return "Native Permission"
	case analysisv1.LinkKind_LINK_KIND_IMPACT:
		return "Impact"
	default:
		return "Link"
	}
}
