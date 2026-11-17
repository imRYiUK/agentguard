package analysis

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"

	analysisv1 "github.com/imRYiUK/agentguard/proto/gen/go/agentguard/analysis/v1"
	snapshotv1 "github.com/imRYiUK/agentguard/proto/gen/go/agentguard/snapshot/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/imRYiUK/agentguard/core/internal/manifest"
	"github.com/imRYiUK/agentguard/core/internal/severity"
)

// RulesVersion is the version of the analysis rules: the policy semantics,
// the Identity Hop rules, and the confidence and severity rules. It is
// written to every result, and changes whenever a rule change can change one.
const RulesVersion = "1"

// DefaultStalenessThreshold is the age past which a Snapshot is a Stale
// Snapshot, unless the caller sets another.
const DefaultStalenessThreshold = 7 * 24 * time.Hour

// snapshotInfo is what analysis keeps of one Snapshot beyond its payload.
type snapshotInfo struct {
	// environment is the name of the Environment in the manifest.
	environment string
	source      string
	id          string
	collectedAt time.Time
	blindSpots  []*snapshotv1.BlindSpot
	stale       bool
}

// markStale flags the Stale Snapshots: those collected more than threshold
// before now. A Snapshot collected in the future counts as fresh.
func markStale(snaps []*snapshotInfo, now time.Time, threshold time.Duration) {
	for _, s := range snaps {
		s.stale = now.Sub(s.collectedAt) > threshold
	}
}

// analysisInput describes the Analysis Input the result was computed from.
// The Snapshots must have been through markStale.
func analysisInput(in Input, m *manifest.Manifest, manifestBytes []byte, snaps []*snapshotInfo) *analysisv1.AnalysisInput {
	sum := sha256.Sum256(manifestBytes)
	out := &analysisv1.AnalysisInput{
		ManifestVersion:    int32(m.Version),
		ManifestDigest:     "sha256:" + hex.EncodeToString(sum[:]),
		AnalyzedAt:         timestamppb.New(in.Now),
		StalenessThreshold: durationpb.New(in.StalenessThreshold),
	}
	for _, s := range snaps {
		out.Snapshots = append(out.Snapshots, &analysisv1.SnapshotRef{
			Environment: s.environment,
			SnapshotId:  s.id,
			Source:      s.source,
			CollectedAt: timestamppb.New(s.collectedAt),
			Stale:       s.stale,
		})
	}
	return out
}

// scorer turns the links of a Reach Path into the path itself, with its
// Confidence.
type scorer struct {
	// ordered are the Snapshots of the Analysis Input in manifest order, and
	// snapshots are the same by their source file, which is what a link's
	// evidence names.
	ordered   []*snapshotInfo
	snapshots map[string]*snapshotInfo
	threshold time.Duration
	resolver  *severity.Resolver
}

func newScorer(snaps []*snapshotInfo, threshold time.Duration, labels []manifest.ResourceSensitivity) *scorer {
	s := &scorer{ordered: snaps, snapshots: map[string]*snapshotInfo{}, threshold: threshold, resolver: severity.NewResolver(labels)}
	for _, snap := range snaps {
		s.snapshots[snap.source] = snap
	}
	return s
}

// blindSpots returns every Blind Spot recorded by the Snapshots of the
// Analysis Input, in manifest order.
func (s *scorer) blindSpots() []*analysisv1.BlindSpot {
	var out []*analysisv1.BlindSpot
	for _, snap := range s.ordered {
		out = append(out, snap.reportedBlindSpots()...)
	}
	return out
}

// reportedBlindSpots returns the Snapshot's Blind Spots for a result.
func (snap *snapshotInfo) reportedBlindSpots() []*analysisv1.BlindSpot {
	var out []*analysisv1.BlindSpot
	for i, b := range snap.blindSpots {
		out = append(out, &analysisv1.BlindSpot{
			Environment: snap.environment,
			SnapshotId:  snap.id,
			Attempted:   b.GetAttempted(),
			Reason:      b.GetReason(),
			Evidence:    &analysisv1.Evidence{Source: snap.source, Location: fmt.Sprintf("$.blindSpots[%d]", i)},
		})
	}
	return out
}

// path assembles a Reach Path from its links. The links are copied, so one
// link shared by several paths is lowered in each only as that path needs.
// A link whose evidence is in a Stale Snapshot has its Confidence reduced.
// Every Blind Spot of a Snapshot the path draws on is listed on the path and
// reduces its Confidence: a Blind Spot has no structure AgentGuard can tie to
// one link, so it cannot be ruled out as affecting any of them. The path's
// Confidence is the weakest of its links, or reduced by a Blind Spot.
func (s *scorer) path(deployment string, structure []string, links []*analysisv1.Link, perm permission) (*analysisv1.ReachPath, error) {
	p := &analysisv1.ReachPath{
		AgentDeployment: deployment,
		Fingerprint:     fingerprint(structure),
		Confidence:      analysisv1.Confidence_CONFIDENCE_HIGH,
	}
	used := map[*snapshotInfo]bool{}
	for _, l := range links {
		if snap := s.snapshots[l.GetEvidence().GetSource()]; snap != nil {
			used[snap] = true
		}
		l = proto.Clone(l).(*analysisv1.Link)
		if snap := s.snapshots[l.GetEvidence().GetSource()]; snap != nil && snap.stale {
			reduce(l, fmt.Sprintf("Stale Snapshot %s: collected at %s, more than %s before the analysis",
				snap.id, snap.collectedAt.UTC().Format(time.RFC3339), s.threshold))
		}
		if l.GetConfidence() == analysisv1.Confidence_CONFIDENCE_REDUCED {
			p.Confidence = analysisv1.Confidence_CONFIDENCE_REDUCED
			if r := l.GetConfidenceReason(); !slices.Contains(p.ConfidenceReasons, r) {
				p.ConfidenceReasons = append(p.ConfidenceReasons, r)
			}
		}
		p.Links = append(p.Links, l)
	}
	for _, snap := range s.ordered {
		if !used[snap] {
			continue
		}
		for _, b := range snap.reportedBlindSpots() {
			p.BlindSpots = append(p.BlindSpots, b)
			p.Confidence = analysisv1.Confidence_CONFIDENCE_REDUCED
			p.ConfidenceReasons = append(p.ConfidenceReasons,
				fmt.Sprintf("Blind Spot in Environment %s: the Collector could not complete %q (%s)", b.Environment, b.Attempted, b.Reason))
		}
	}
	sensitivity, err := s.resolver.Sensitivity(perm.resource)
	if err != nil {
		return nil, fmt.Errorf("Reach Path of %s: %w", perm.link.GetLabel(), err)
	}
	p.ResourceSensitivity = sensitivityEnum[sensitivity]
	p.Severity = severityEnum[severity.Of(perm.impactName, sensitivity)]
	return p, nil
}

var sensitivityEnum = map[string]analysisv1.Sensitivity{
	severity.Unknown:             analysisv1.Sensitivity_SENSITIVITY_UNKNOWN,
	manifest.SensitivityLow:      analysisv1.Sensitivity_SENSITIVITY_LOW,
	manifest.SensitivityMedium:   analysisv1.Sensitivity_SENSITIVITY_MEDIUM,
	manifest.SensitivityHigh:     analysisv1.Sensitivity_SENSITIVITY_HIGH,
	manifest.SensitivityCritical: analysisv1.Sensitivity_SENSITIVITY_CRITICAL,
}

var severityEnum = map[string]analysisv1.Severity{
	severity.Unknown:  analysisv1.Severity_SEVERITY_UNKNOWN,
	severity.Low:      analysisv1.Severity_SEVERITY_LOW,
	severity.Medium:   analysisv1.Severity_SEVERITY_MEDIUM,
	severity.High:     analysisv1.Severity_SEVERITY_HIGH,
	severity.Critical: analysisv1.Severity_SEVERITY_CRITICAL,
}

// reduce lowers a link's Confidence and adds the reason to those it has.
func reduce(l *analysisv1.Link, reason string) {
	l.Confidence = analysisv1.Confidence_CONFIDENCE_REDUCED
	if l.ConfidenceReason == "" {
		l.ConfidenceReason = reason
		return
	}
	l.ConfidenceReason = strings.Join([]string{l.ConfidenceReason, reason}, "; ")
}

// fingerprint derives a Reach Path Fingerprint from the parts that make up the
// structure of a path. Each part is length-prefixed, so no two different
// lists of parts give the same bytes. The "rpf1" prefix names this encoding:
// a change to it must use a new prefix, since fingerprints are kept across
// analyses.
func fingerprint(structure []string) string {
	h := sha256.New()
	for _, part := range structure {
		fmt.Fprintf(h, "%d:%s;", len(part), part)
	}
	return "rpf1:" + hex.EncodeToString(h.Sum(nil))
}
