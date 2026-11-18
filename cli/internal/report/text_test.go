package report_test

import (
	"math/rand"
	"slices"
	"strings"
	"testing"
	"time"

	analysisv1 "github.com/imRYiUK/agentguard/proto/gen/go/agentguard/analysis/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/imRYiUK/agentguard/cli/internal/report"
)

func path(fingerprint string, severity analysisv1.Severity) *analysisv1.ReachPath {
	return &analysisv1.ReachPath{
		AgentDeployment:     "deploy-agent",
		Fingerprint:         fingerprint,
		Severity:            severity,
		ResourceSensitivity: analysisv1.Sensitivity_SENSITIVITY_CRITICAL,
		Confidence:          analysisv1.Confidence_CONFIDENCE_HIGH,
		Links: []*analysisv1.Link{
			{
				Kind:       analysisv1.LinkKind_LINK_KIND_TOOL,
				Label:      "shell Tool (MCP server shell)",
				Evidence:   &analysisv1.Evidence{Source: ".mcp.json", Location: "$.mcpServers.shell"},
				Confidence: analysisv1.Confidence_CONFIDENCE_HIGH,
			},
			{
				Kind:       analysisv1.LinkKind_LINK_KIND_IDENTITY,
				Label:      "Linux user deploy (uid 1001)",
				Evidence:   &analysisv1.Evidence{Source: "snapshots/linux.json", Location: "$.linux.agentUser"},
				Confidence: analysisv1.Confidence_CONFIDENCE_HIGH,
				Origin:     analysisv1.BindingOrigin_BINDING_ORIGIN_DISCOVERED,
			},
			{
				Kind:       analysisv1.LinkKind_LINK_KIND_IMPACT,
				Label:      "Destroy Data",
				Evidence:   &analysisv1.Evidence{Source: "agentguard:impact-mappings/v2", Location: "$.mappings[3]"},
				Confidence: analysisv1.Confidence_CONFIDENCE_HIGH,
			},
		},
	}
}

func text(t *testing.T, r *analysisv1.AnalysisResult) string {
	t.Helper()
	return string(report.Text(r))
}

func TestTextShowsEveryLinkWithItsEvidence(t *testing.T) {
	out := text(t, &analysisv1.AnalysisResult{
		ReachPaths: []*analysisv1.ReachPath{path("rpf1:aaa", analysisv1.Severity_SEVERITY_CRITICAL)},
	})
	for _, want := range []string{
		"critical",
		"deploy-agent",
		"rpf1:aaa",
		"shell Tool (MCP server shell)",
		".mcp.json $.mcpServers.shell",
		"Linux user deploy (uid 1001)",
		"discovered",
		"snapshots/linux.json $.linux.agentUser",
		"Destroy Data",
		"agentguard:impact-mappings/v2 $.mappings[3]",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the text must contain %q, got:\n%s", want, out)
		}
	}
	if !strings.HasSuffix(out, "\n") {
		t.Errorf("the text must end with a newline, got %q", out[max(0, len(out)-10):])
	}
}

func TestTextSaysWhyConfidenceIsReduced(t *testing.T) {
	p := path("rpf1:aaa", analysisv1.Severity_SEVERITY_HIGH)
	p.Confidence = analysisv1.Confidence_CONFIDENCE_REDUCED
	p.ConfidenceReasons = []string{"Stale Snapshot snap-1: collected long ago"}
	p.Links[1].Confidence = analysisv1.Confidence_CONFIDENCE_REDUCED
	p.Links[1].ConfidenceReason = "Stale Snapshot snap-1: collected long ago"
	out := text(t, &analysisv1.AnalysisResult{ReachPaths: []*analysisv1.ReachPath{p}})
	for _, want := range []string{"reduced", "Stale Snapshot snap-1: collected long ago"} {
		if !strings.Contains(out, want) {
			t.Errorf("the text must contain %q, got:\n%s", want, out)
		}
	}
}

func TestTextSummarizesReachPathsBySeverityAndCountsUnknown(t *testing.T) {
	out := text(t, &analysisv1.AnalysisResult{ReachPaths: []*analysisv1.ReachPath{
		path("rpf1:a", analysisv1.Severity_SEVERITY_CRITICAL),
		path("rpf1:b", analysisv1.Severity_SEVERITY_UNKNOWN),
		path("rpf1:c", analysisv1.Severity_SEVERITY_UNKNOWN),
		path("rpf1:d", analysisv1.Severity_SEVERITY_LOW),
	}})
	want := "4 Reach Paths: 1 critical, 0 high, 0 medium, 1 low, 2 unknown"
	if !strings.Contains(out, want) {
		t.Errorf("the summary must say %q, got:\n%s", want, out)
	}
}

func TestTextSaysWhenThereAreNoReachPaths(t *testing.T) {
	out := text(t, &analysisv1.AnalysisResult{})
	if !strings.Contains(out, "No Reach Paths found") {
		t.Errorf("an empty result must say so, got:\n%s", out)
	}
}

func TestTextListsMostSevereReachPathsFirst(t *testing.T) {
	paths := []*analysisv1.ReachPath{
		path("rpf1:unknown", analysisv1.Severity_SEVERITY_UNKNOWN),
		path("rpf1:medium", analysisv1.Severity_SEVERITY_MEDIUM),
		path("rpf1:critical-b", analysisv1.Severity_SEVERITY_CRITICAL),
		path("rpf1:low", analysisv1.Severity_SEVERITY_LOW),
		path("rpf1:critical-a", analysisv1.Severity_SEVERITY_CRITICAL),
		path("rpf1:high", analysisv1.Severity_SEVERITY_HIGH),
	}
	out := text(t, &analysisv1.AnalysisResult{ReachPaths: paths})
	want := []string{"rpf1:critical-a", "rpf1:critical-b", "rpf1:high", "rpf1:medium", "rpf1:low", "rpf1:unknown"}
	var at []int
	for _, fp := range want {
		at = append(at, strings.Index(out, fp))
	}
	if slices.Contains(at, -1) || !slices.IsSorted(at) {
		t.Errorf("want the order %v (by severity, then fingerprint), got positions %v in\n%s", want, at, out)
	}
}

func TestTextIsTheSameWhateverOrderTheResultListsThings(t *testing.T) {
	build := func() *analysisv1.AnalysisResult {
		return &analysisv1.AnalysisResult{
			ReachPaths: []*analysisv1.ReachPath{
				path("rpf1:1", analysisv1.Severity_SEVERITY_HIGH),
				path("rpf1:2", analysisv1.Severity_SEVERITY_HIGH),
				path("rpf1:3", analysisv1.Severity_SEVERITY_LOW),
				path("rpf1:4", analysisv1.Severity_SEVERITY_UNKNOWN),
			},
		}
	}
	want := text(t, build())
	rng := rand.New(rand.NewSource(1))
	for range 20 {
		r := build()
		rng.Shuffle(len(r.ReachPaths), func(i, j int) { r.ReachPaths[i], r.ReachPaths[j] = r.ReachPaths[j], r.ReachPaths[i] })
		if got := text(t, r); got != want {
			t.Fatalf("the text depends on the order of the result's Reach Paths:\n--- got ---\n%s\n--- want ---\n%s", got, want)
		}
	}
}

func TestTextDoesNotChangeTheResult(t *testing.T) {
	r := &analysisv1.AnalysisResult{ReachPaths: []*analysisv1.ReachPath{
		path("rpf1:b", analysisv1.Severity_SEVERITY_LOW),
		path("rpf1:a", analysisv1.Severity_SEVERITY_CRITICAL),
	}}
	before := proto.Clone(r)
	text(t, r)
	if !proto.Equal(r, before) {
		t.Error("Text reordered or modified the result it was given")
	}
}

func TestTextReportsSecondaryFindingsAndBlindSpots(t *testing.T) {
	out := text(t, &analysisv1.AnalysisResult{
		SecondaryFindings: []*analysisv1.SecondaryFinding{{
			Kind:            analysisv1.SecondaryFindingKind_SECONDARY_FINDING_KIND_UNRESTRICTED_COMMAND_EXECUTION,
			AgentDeployment: "deploy-agent",
			Label:           "MCP server shell gives unrestricted command execution",
			Evidence:        &analysisv1.Evidence{Source: ".mcp.json", Location: "$.mcpServers.shell"},
			Confidence:      analysisv1.Confidence_CONFIDENCE_HIGH,
		}},
		BlindSpots: []*analysisv1.BlindSpot{{
			Environment: "build-host",
			SnapshotId:  "snap-linux-0001",
			Attempted:   "read /etc/sudoers",
			Reason:      "permission denied",
			Evidence:    &analysisv1.Evidence{Source: "snapshots/linux.json", Location: "$.blindSpots[0]"},
		}},
	})
	for _, want := range []string{
		"Secondary Findings",
		"MCP server shell gives unrestricted command execution",
		".mcp.json $.mcpServers.shell",
		"Blind Spots",
		"build-host",
		"read /etc/sudoers",
		"permission denied",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the text must contain %q, got:\n%s", want, out)
		}
	}
}

func TestTextNamesTheAnalysisInput(t *testing.T) {
	at := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	out := text(t, &analysisv1.AnalysisResult{
		ImpactMappingVersion: "2",
		RulesVersion:         "1",
		AnalysisInput: &analysisv1.AnalysisInput{
			ManifestDigest:     "sha256:abc",
			AnalyzedAt:         timestamppb.New(at),
			StalenessThreshold: durationpb.New(7 * 24 * time.Hour),
			Snapshots: []*analysisv1.SnapshotRef{
				{Environment: "build-host", SnapshotId: "snap-linux-0001", CollectedAt: timestamppb.New(at.Add(-2 * time.Hour))},
				{Environment: "prod-aws", SnapshotId: "snap-aws-0001", CollectedAt: timestamppb.New(at.Add(-200 * time.Hour)), Stale: true},
			},
		},
	})
	for _, want := range []string{
		"2026-11-17T12:00:00Z",
		"sha256:abc",
		"build-host", "snap-linux-0001",
		"prod-aws", "snap-aws-0001", "stale",
		"Impact mapping version 2",
		"rules version 1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the text must contain %q, got:\n%s", want, out)
		}
	}
}

func TestTextUsesTheSingularForOneReachPath(t *testing.T) {
	out := text(t, &analysisv1.AnalysisResult{ReachPaths: []*analysisv1.ReachPath{path("rpf1:a", analysisv1.Severity_SEVERITY_LOW)}})
	if !strings.Contains(out, "1 Reach Path: ") {
		t.Errorf("want %q in\n%s", "1 Reach Path: ", out)
	}
}
