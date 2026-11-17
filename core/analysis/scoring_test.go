package analysis_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	analysisv1 "github.com/imRYiUK/agentguard/proto/gen/go/agentguard/analysis/v1"

	"github.com/imRYiUK/agentguard/core/analysis"
)

// now is a moment shortly after both fixture Snapshots were collected (the
// Linux one at 10:00, the AWS one at 10:05 on 2026-11-17).
var now = time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)

func analyzeAt(t *testing.T, files analysis.Input) *analysisv1.AnalysisResult {
	t.Helper()
	if files.Now.IsZero() {
		files.Now = now
	}
	result, err := analysis.Analyze(files)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestAnalyzeRecordsTheAnalysisInputAndVersions(t *testing.T) {
	files := fixtureFiles(t, "version: 1", "version: 1")
	result := analyzeAt(t, analysis.Input{Files: files})

	in := result.GetAnalysisInput()
	if got := in.GetManifestVersion(); got != 1 {
		t.Errorf("manifest version = %d, want 1", got)
	}
	sum := sha256.Sum256(files[analysis.ManifestFile].Data)
	if got, want := in.GetManifestDigest(), "sha256:"+hex.EncodeToString(sum[:]); got != want {
		t.Errorf("manifest digest = %q, want %q", got, want)
	}
	var got [][3]string
	for _, s := range in.GetSnapshots() {
		got = append(got, [3]string{s.GetEnvironment(), s.GetSnapshotId(), s.GetSource()})
		if s.GetStale() {
			t.Errorf("Snapshot %s is two hours old and must not be stale", s.GetSnapshotId())
		}
	}
	want := [][3]string{
		{"build-host", "snap-linux-0001", "snapshots/linux.json"},
		{"prod-aws", "snap-aws-0001", "snapshots/aws.json"},
	}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("Snapshots = %v, want %v", got, want)
	}
	if at := in.GetSnapshots()[0].GetCollectedAt().AsTime(); !at.Equal(time.Date(2026, 11, 17, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("Snapshot collected at %v, want 10:00", at)
	}
	if !in.GetAnalyzedAt().AsTime().Equal(now) {
		t.Errorf("analyzed at %v, want %v", in.GetAnalyzedAt().AsTime(), now)
	}
	if got, want := in.GetStalenessThreshold().AsDuration(), analysis.DefaultStalenessThreshold; got != want {
		t.Errorf("staleness threshold = %v, want the default %v", got, want)
	}
	if analysis.DefaultStalenessThreshold != 7*24*time.Hour {
		t.Errorf("the documented default staleness threshold is 7 days, got %v", analysis.DefaultStalenessThreshold)
	}
	if result.GetRulesVersion() == "" || result.GetRulesVersion() != analysis.RulesVersion {
		t.Errorf("rules version = %q, want %q", result.GetRulesVersion(), analysis.RulesVersion)
	}
	if result.GetImpactMappingVersion() == "" {
		t.Error("the Impact mapping version is still recorded")
	}
}

// withoutBlindSpots returns the files with every Snapshot's Blind Spots
// removed, so a test can look at one lowering of Confidence on its own.
func withoutBlindSpots(t *testing.T, files fstest.MapFS) fstest.MapFS {
	t.Helper()
	for _, name := range []string{"snapshots/linux.json", "snapshots/aws.json"} {
		var snap map[string]any
		if err := json.Unmarshal(files[name].Data, &snap); err != nil {
			t.Fatal(err)
		}
		delete(snap, "blindSpots")
		out, err := json.Marshal(snap)
		if err != nil {
			t.Fatal(err)
		}
		files[name] = &fstest.MapFile{Data: out}
	}
	return files
}

func reasonsContain(p *analysisv1.ReachPath, text string) bool {
	return slices.ContainsFunc(p.GetConfidenceReasons(), func(r string) bool { return strings.Contains(r, text) })
}

func TestFreshSnapshotsKeepConfidenceHigh(t *testing.T) {
	files := withoutBlindSpots(t, fixtureFiles(t, "version: 1", "version: 1"))
	result := analyzeAt(t, analysis.Input{Files: files})
	if len(result.ReachPaths) == 0 {
		t.Fatal("want Reach Paths")
	}
	for _, p := range result.ReachPaths {
		if p.Confidence != analysisv1.Confidence_CONFIDENCE_HIGH || len(p.ConfidenceReasons) != 0 {
			t.Errorf("a path over fresh Snapshots with no Blind Spots has high confidence and no reasons, got %v %v", p.Confidence, p.ConfidenceReasons)
		}
	}
}

func TestStaleSnapshotLowersConfidenceOfEveryPathThatUsesIt(t *testing.T) {
	// The AWS Snapshot was collected at 10:05 and the Linux one at 10:00.
	// With a one-hour threshold at 11:03 the Linux one is stale (63 minutes)
	// and the AWS one is not (58 minutes).
	at := time.Date(2026, 11, 17, 11, 3, 0, 0, time.UTC)
	files := withoutBlindSpots(t, fixtureFiles(t, "version: 1", "version: 1"))
	result := analyzeAt(t, analysis.Input{Files: files, Now: at, StalenessThreshold: time.Hour})

	stale := map[string]bool{}
	for _, s := range result.AnalysisInput.Snapshots {
		stale[s.SnapshotId] = s.Stale
	}
	if !stale["snap-linux-0001"] || stale["snap-aws-0001"] {
		t.Errorf("stale Snapshots = %v, want only snap-linux-0001", stale)
	}
	if len(result.ReachPaths) == 0 {
		t.Fatal("want Reach Paths")
	}
	for _, p := range result.ReachPaths {
		if p.Confidence != analysisv1.Confidence_CONFIDENCE_REDUCED {
			t.Errorf("a path through a Stale Snapshot must have reduced confidence, got %v", p.Confidence)
		}
		if !reasonsContain(p, "Stale Snapshot snap-linux-0001") || reasonsContain(p, "snap-aws-0001") {
			t.Errorf("want a reason naming the stale Snapshot only, got %q", p.ConfidenceReasons)
		}
		for _, l := range p.Links {
			fromLinux := l.Evidence.Source == "snapshots/linux.json"
			if fromLinux != (l.Confidence == analysisv1.Confidence_CONFIDENCE_REDUCED && strings.Contains(l.ConfidenceReason, "Stale Snapshot")) {
				t.Errorf("link %q (%s): confidence %v, reason %q; links from the stale Snapshot, and only those, are marked", l.Label, l.Evidence.Source, l.Confidence, l.ConfidenceReason)
			}
		}
	}
}

func TestSnapshotExactlyAtTheThresholdIsNotStale(t *testing.T) {
	at := time.Date(2026, 11, 17, 11, 0, 0, 0, time.UTC) // linux is exactly 1h old, aws 55m
	files := withoutBlindSpots(t, fixtureFiles(t, "version: 1", "version: 1"))
	result := analyzeAt(t, analysis.Input{Files: files, Now: at, StalenessThreshold: time.Hour})
	for _, s := range result.AnalysisInput.Snapshots {
		if s.Stale {
			t.Errorf("Snapshot %s is exactly at the threshold and must not be stale", s.SnapshotId)
		}
	}
}

// withBlindSpots returns the files with the Blind Spots of one Snapshot file
// replaced.
func withBlindSpots(t *testing.T, files fstest.MapFS, name string, spots ...map[string]string) fstest.MapFS {
	t.Helper()
	var snap map[string]any
	if err := json.Unmarshal(files[name].Data, &snap); err != nil {
		t.Fatal(err)
	}
	var list []any
	for _, s := range spots {
		list = append(list, s)
	}
	snap["blindSpots"] = list
	out, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	files[name] = &fstest.MapFile{Data: out}
	return files
}

func TestBlindSpotsOfTheSnapshotsAChainUsesAreListedOnThePathAndLowerItsConfidence(t *testing.T) {
	files := withoutBlindSpots(t, fixtureFiles(t, "version: 1", "version: 1"))
	files = withBlindSpots(t, files, "snapshots/linux.json",
		map[string]string{"attempted": "read /etc/sudoers", "reason": "permission denied"})
	files = withBlindSpots(t, files, "snapshots/aws.json",
		map[string]string{"attempted": "organizations:ListPolicies (SCPs)", "reason": "not collected"},
		map[string]string{"attempted": "iam:GetAccountAuthorizationDetails", "reason": "access denied"})
	result := analyzeAt(t, analysis.Input{Files: files})

	if len(result.ReachPaths) == 0 {
		t.Fatal("want Reach Paths")
	}
	for _, p := range result.ReachPaths {
		var got []string
		for _, b := range p.BlindSpots {
			got = append(got, b.Environment+" | "+b.SnapshotId+" | "+b.Attempted+" | "+b.Reason+" | "+b.Evidence.Source+" "+b.Evidence.Location)
		}
		want := []string{
			"build-host | snap-linux-0001 | read /etc/sudoers | permission denied | snapshots/linux.json $.blindSpots[0]",
			"prod-aws | snap-aws-0001 | organizations:ListPolicies (SCPs) | not collected | snapshots/aws.json $.blindSpots[0]",
			"prod-aws | snap-aws-0001 | iam:GetAccountAuthorizationDetails | access denied | snapshots/aws.json $.blindSpots[1]",
		}
		if !slices.Equal(got, want) {
			t.Errorf("path Blind Spots =\n%q\nwant\n%q", got, want)
		}
		if p.Confidence != analysisv1.Confidence_CONFIDENCE_REDUCED {
			t.Errorf("a Blind Spot lowers the path's confidence, got %v", p.Confidence)
		}
		if !reasonsContain(p, "Blind Spot") || !reasonsContain(p, "read /etc/sudoers") {
			t.Errorf("want a reason naming the Blind Spot, got %q", p.ConfidenceReasons)
		}
		for _, l := range p.Links {
			if l.Confidence != analysisv1.Confidence_CONFIDENCE_HIGH {
				t.Errorf("a Blind Spot lowers the path, not each link; link %q has %v", l.Label, l.Confidence)
			}
		}
	}
}

func TestResultListsEveryBlindSpotOfTheAnalysisInput(t *testing.T) {
	files := fixtureFiles(t, "version: 1", "version: 1")
	result := analyzeAt(t, analysis.Input{Files: files})
	var got []string
	for _, b := range result.BlindSpots {
		got = append(got, b.Environment+"|"+b.Attempted)
	}
	want := []string{"build-host|read /etc/sudoers", "prod-aws|organizations:ListPolicies (SCPs)"}
	if !slices.Equal(got, want) {
		t.Errorf("result Blind Spots = %q, want %q", got, want)
	}
}

func TestUnreadableCredentialFileIsABlindSpotNotAPath(t *testing.T) {
	// The Collector was denied reading the credential file, so the Snapshot
	// has no entry for it, only a Blind Spot. Analysis must neither invent
	// the path nor drop the fact.
	files := fixtureFiles(t, "version: 1", "version: 1")
	var snap map[string]any
	if err := json.Unmarshal(files["snapshots/linux.json"].Data, &snap); err != nil {
		t.Fatal(err)
	}
	delete(snap["linux"].(map[string]any), "credentialFiles")
	out, _ := json.Marshal(snap)
	files["snapshots/linux.json"] = &fstest.MapFile{Data: out}
	files = withBlindSpots(t, files, "snapshots/linux.json",
		map[string]string{"attempted": "read /home/ops/.aws/credentials", "reason": "permission denied"})

	result := analyzeAt(t, analysis.Input{Files: files})
	if len(result.ReachPaths) != 0 {
		t.Errorf("want no Reach Path, got %d", len(result.ReachPaths))
	}
	if !slices.ContainsFunc(result.BlindSpots, func(b *analysisv1.BlindSpot) bool {
		return b.Attempted == "read /home/ops/.aws/credentials" && b.Reason == "permission denied"
	}) {
		t.Errorf("want the unreadable credential file reported as a Blind Spot, got %v", result.BlindSpots)
	}
}

// withSensitivity returns the files with Resource Sensitivity labels added to
// the manifest. Each label is "resource=level".
func withSensitivity(t *testing.T, files fstest.MapFS, labels ...string) fstest.MapFS {
	t.Helper()
	var yaml strings.Builder
	yaml.WriteString("resourceSensitivity:\n")
	for _, l := range labels {
		resource, level, _ := strings.Cut(l, "=")
		yaml.WriteString("  - resource: \"" + resource + "\"\n    sensitivity: " + level + "\n")
	}
	m := string(files[analysis.ManifestFile].Data)
	files[analysis.ManifestFile] = &fstest.MapFile{Data: []byte(strings.Replace(m, "environments:", yaml.String()+"environments:", 1))}
	return files
}

func TestSeverityIsImpactTimesResourceSensitivity(t *testing.T) {
	policy := `[
		{"Effect":"Allow","Action":"s3:DeleteObject","Resource":"arn:aws:s3:::prod-billing/*"},
		{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::logs-2026/*"},
		{"Effect":"Allow","Action":"s3:PutObject","Resource":"arn:aws:s3:::scratch/*"},
		{"Effect":"Allow","Action":"ec2:RunInstances","Resource":"arn:aws:s3:::prod-billing/*"}]`
	files := withSensitivity(t, withPolicy(t, policy), "arn:aws:s3:::prod-*=critical", "arn:aws:s3:::logs-*=low")
	result := analyzeAt(t, analysis.Input{Files: files})

	got := map[string]string{}
	for _, p := range result.ReachPaths {
		var perm, imp string
		for _, l := range p.Links {
			switch l.Kind {
			case analysisv1.LinkKind_LINK_KIND_NATIVE_PERMISSION:
				perm = l.Label
			case analysisv1.LinkKind_LINK_KIND_IMPACT:
				imp = l.Label
			}
		}
		got[perm+" => "+imp] = p.ResourceSensitivity.String() + " / " + p.Severity.String()
	}
	want := map[string]string{
		// Destroy Data (3) on a critical resource (4): critical.
		"Allow s3:DeleteObject on arn:aws:s3:::prod-billing/* => Destroy Data": "SENSITIVITY_CRITICAL / SEVERITY_CRITICAL",
		// Read Data (1) on a low resource (1): low.
		"Allow s3:GetObject on arn:aws:s3:::logs-2026/* => Read Data": "SENSITIVITY_LOW / SEVERITY_LOW",
		// No label applies, so neither is guessed.
		"Allow s3:PutObject on arn:aws:s3:::scratch/* => Modify Data": "SENSITIVITY_UNKNOWN / SEVERITY_UNKNOWN",
		// A label applies, but the Impact is unknown.
		"Allow ec2:RunInstances on arn:aws:s3:::prod-billing/* => unknown": "SENSITIVITY_CRITICAL / SEVERITY_UNKNOWN",
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s: sensitivity / severity = %q, want %q", k, got[k], w)
		}
	}
	if len(got) != len(want) {
		t.Errorf("got paths %v, want %d", got, len(want))
	}
}

func TestWithoutLabelsEverySeverityIsUnknown(t *testing.T) {
	result := analyzeAt(t, analysis.Input{Files: fixtureFiles(t, "version: 1", "version: 1")})
	for _, p := range result.ReachPaths {
		if p.Severity != analysisv1.Severity_SEVERITY_UNKNOWN || p.ResourceSensitivity != analysisv1.Sensitivity_SENSITIVITY_UNKNOWN {
			t.Errorf("no label applies, so severity and sensitivity are unknown, got %v / %v", p.Severity, p.ResourceSensitivity)
		}
	}
}

func TestNotResourceGrantReachesEveryLabel(t *testing.T) {
	files := withSensitivity(t, withPolicy(t,
		`[{"Effect":"Allow","Action":"s3:GetObject","NotResource":"arn:aws:s3:::public/*"}]`),
		"arn:aws:s3:::prod-*=high")
	result := analyzeAt(t, analysis.Input{Files: files})
	if len(result.ReachPaths) != 1 || result.ReachPaths[0].ResourceSensitivity != analysisv1.Sensitivity_SENSITIVITY_HIGH {
		t.Errorf("a NotResource grant reaches everything it does not exclude, want one path of high sensitivity, got %v", result.ReachPaths)
	}
}

// editSnapshot returns the files with one Snapshot file changed by edit.
func editSnapshot(t *testing.T, files fstest.MapFS, name string, edit func(snap map[string]any)) fstest.MapFS {
	t.Helper()
	var snap map[string]any
	if err := json.Unmarshal(files[name].Data, &snap); err != nil {
		t.Fatal(err)
	}
	edit(snap)
	out, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	files[name] = &fstest.MapFile{Data: out}
	return files
}

// replaceIn returns the files with old replaced by new in one file, which
// must contain old.
func replaceIn(t *testing.T, files fstest.MapFS, name, old, new string) fstest.MapFS {
	t.Helper()
	content := string(files[name].Data)
	if !strings.Contains(content, old) {
		t.Fatalf("%s has no %q to replace", name, old)
	}
	files[name] = &fstest.MapFile{Data: []byte(strings.ReplaceAll(content, old, new))}
	return files
}

// fingerprints returns the sorted Reach Path Fingerprints of an analysis.
func fingerprints(t *testing.T, in analysis.Input) []string {
	t.Helper()
	result := analyzeAt(t, in)
	var out []string
	for _, p := range result.ReachPaths {
		out = append(out, p.Fingerprint)
	}
	slices.Sort(out)
	return out
}

func TestEveryReachPathHasADistinctFingerprint(t *testing.T) {
	// One s3:* grant gives several Impacts, and each is its own path.
	result := analyzeAt(t, analysis.Input{Files: fixtureFiles(t, "version: 1", "version: 1")})
	if len(result.ReachPaths) < 2 {
		t.Fatal("want several Reach Paths")
	}
	seen := map[string]bool{}
	for _, p := range result.ReachPaths {
		if !strings.HasPrefix(p.Fingerprint, "rpf1:") || len(p.Fingerprint) != len("rpf1:")+64 {
			t.Errorf("fingerprint %q is not rpf1: and 64 hex digits", p.Fingerprint)
		}
		if seen[p.Fingerprint] {
			t.Errorf("fingerprint %s is shared by two paths", p.Fingerprint)
		}
		seen[p.Fingerprint] = true
	}
}

func TestFingerprintIgnoresEvidenceDetails(t *testing.T) {
	base := func() fstest.MapFS { return fixtureFiles(t, "version: 1", "version: 1") }
	want := fingerprints(t, analysis.Input{Files: base()})
	if len(want) == 0 {
		t.Fatal("want Reach Paths")
	}
	tests := []struct {
		name string
		in   func() analysis.Input
	}{
		{"Snapshot IDs", func() analysis.Input {
			f := replaceIn(t, base(), "snapshots/linux.json", "snap-linux-0001", "snap-linux-7777")
			return analysis.Input{Files: replaceIn(t, f, "snapshots/aws.json", "snap-aws-0001", "snap-aws-7777")}
		}},
		{"collection times", func() analysis.Input {
			f := replaceIn(t, base(), "snapshots/linux.json", "2026-11-17T10:00:00Z", "2026-11-17T11:30:00Z")
			return analysis.Input{Files: f}
		}},
		{"a Stale Snapshot", func() analysis.Input {
			return analysis.Input{Files: base(), Now: now.Add(90 * 24 * time.Hour)}
		}},
		{"Blind Spots", func() analysis.Input {
			return analysis.Input{Files: withoutBlindSpots(t, base())}
		}},
		{"Resource Sensitivity labels", func() analysis.Input {
			return analysis.Input{Files: withSensitivity(t, base(), "*=critical")}
		}},
		{"the file a Snapshot is stored in", func() analysis.Input {
			f := replaceIn(t, base(), analysis.ManifestFile, "snapshots/aws.json", "evidence/aws-2026.json")
			f["evidence/aws-2026.json"] = f["snapshots/aws.json"]
			delete(f, "snapshots/aws.json")
			return analysis.Input{Files: f}
		}},
		{"the file a Tool is declared in", func() analysis.Input {
			f := replaceIn(t, base(), analysis.ManifestFile, ".mcp.json", "tools/mcp.json")
			f["tools/mcp.json"] = f[".mcp.json"]
			delete(f, ".mcp.json")
			return analysis.Input{Files: f}
		}},
		{"where in a policy the statement is", func() analysis.Input {
			f := editSnapshot(t, base(), "snapshots/aws.json", func(snap map[string]any) {
				doc := snap["aws"].(map[string]any)["identities"].([]any)[0].(map[string]any)["policies"].([]any)[0].(map[string]any)["document"].(map[string]any)
				doc["Statement"] = append([]any{map[string]any{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": "*"}}, doc["Statement"].([]any)...)
			})
			return analysis.Input{Files: f}
		}},
		{"the name of a policy", func() analysis.Input {
			return analysis.Input{Files: replaceIn(t, base(), "snapshots/aws.json", "ops-access", "renamed-policy")}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := fingerprints(t, tc.in())
			// A new unrelated grant adds paths; those already there must keep
			// their fingerprints.
			for _, fp := range want {
				if !slices.Contains(got, fp) {
					t.Errorf("fingerprint %s changed with only evidence details", fp)
				}
			}
		})
	}
}

func TestFingerprintChangesWithStructure(t *testing.T) {
	base := func() fstest.MapFS { return fixtureFiles(t, "version: 1", "version: 1") }
	want := fingerprints(t, analysis.Input{Files: base()})
	tests := []struct {
		name string
		in   func() analysis.Input
		// partial is set when the change touches only some of the paths, so
		// the others keep their fingerprints.
		partial bool
	}{
		{name: "the Agent Deployment", in: func() analysis.Input {
			return analysis.Input{Files: replaceIn(t, base(), analysis.ManifestFile, "name: deploy-agent", "name: other-agent")}
		}},
		{name: "the Tool", in: func() analysis.Input {
			f := replaceIn(t, base(), ".mcp.json", `"shell": {`, `"sh": {`)
			f = replaceIn(t, f, ".claude/settings.json", `"shell"`, `"sh"`)
			return analysis.Input{Files: f}
		}},
		{name: "the Native Permission's action", partial: true, in: func() analysis.Input {
			return analysis.Input{Files: replaceIn(t, base(), "snapshots/aws.json", `"s3:*"`, `"s3:Get*"`)}
		}},
		{name: "the resource pattern", partial: true, in: func() analysis.Input {
			return analysis.Input{Files: replaceIn(t, base(), "snapshots/aws.json", `"Resource": "*"`, `"Resource": "arn:aws:s3:::dev-*"`)}
		}},
		{name: "the Linux user", in: func() analysis.Input {
			f := editSnapshot(t, base(), "snapshots/linux.json", func(snap map[string]any) {
				snap["linux"].(map[string]any)["agentUser"].(map[string]any)["name"] = "builder"
			})
			return analysis.Input{Files: f}
		}},
		{name: "the credential file the chain goes through", in: func() analysis.Input {
			return analysis.Input{Files: replaceIn(t, base(), "snapshots/linux.json", "/home/ops/.aws/credentials", "/home/ops/.aws/other")}
		}},
		{name: "the Environment", in: func() analysis.Input {
			f := replaceIn(t, base(), analysis.ManifestFile, "e8c913f01b6f9ef3d7f19c3cef1cc390", "00000000000000000000000000000001")
			f = replaceIn(t, f, "snapshots/linux.json", "e8c913f01b6f9ef3d7f19c3cef1cc390", "00000000000000000000000000000001")
			return analysis.Input{Files: f}
		}},
		{name: "the AWS Identity", in: func() analysis.Input {
			return analysis.Input{Files: replaceIn(t, base(), "snapshots/aws.json", "role/ops", "role/ops2")}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := fingerprints(t, tc.in())
			if len(got) == 0 {
				t.Fatal("want Reach Paths")
			}
			changed := 0
			for _, fp := range got {
				if !slices.Contains(want, fp) {
					changed++
				} else if !tc.partial {
					t.Errorf("fingerprint %s survived a change of structure", fp)
				}
			}
			if changed == 0 {
				t.Error("no fingerprint changed")
			}
		})
	}
}

func TestTwoStatementsGrantingTheSameThingGiveOneReachPath(t *testing.T) {
	// The same Native Permission twice, once conditional. They are one
	// finding, so one fingerprint, and it keeps the more certain grant.
	files := withoutBlindSpots(t, withPolicy(t, `[
		{"Effect":"Allow","Action":"s3:DeleteObject","Resource":"*","Condition":{"Bool":{"aws:SecureTransport":"true"}}},
		{"Effect":"Allow","Action":"s3:DeleteObject","Resource":"*"}]`))
	result := analyzeAt(t, analysis.Input{Files: files})
	if len(result.ReachPaths) != 1 {
		t.Fatalf("want one Reach Path, got %d", len(result.ReachPaths))
	}
	if result.ReachPaths[0].Confidence != analysisv1.Confidence_CONFIDENCE_HIGH {
		t.Errorf("want the unconditional grant to win, got %v", result.ReachPaths[0].Confidence)
	}
}

func TestFingerprintIgnoresTheOrderOfNotResourceEntries(t *testing.T) {
	a := withPolicy(t, `[{"Effect":"Allow","Action":"s3:GetObject","NotResource":["arn:aws:s3:::a/*","arn:aws:s3:::b/*"]}]`)
	b := withPolicy(t, `[{"Effect":"Allow","Action":"s3:GetObject","NotResource":["arn:aws:s3:::b/*","arn:aws:s3:::a/*"]}]`)
	fa, fb := fingerprints(t, analysis.Input{Files: a}), fingerprints(t, analysis.Input{Files: b})
	if len(fa) != 1 || !slices.Equal(fa, fb) {
		t.Errorf("the same exclusions in another order are the same structure: %v vs %v", fa, fb)
	}
}

func TestAnalyzeRejectsANegativeStalenessThreshold(t *testing.T) {
	_, err := analysis.Analyze(analysis.Input{Files: fixtureFiles(t, "version: 1", "version: 1"), StalenessThreshold: -time.Hour})
	if err == nil || !strings.Contains(err.Error(), "staleness threshold") {
		t.Errorf("want an error about the staleness threshold, got %v", err)
	}
}
