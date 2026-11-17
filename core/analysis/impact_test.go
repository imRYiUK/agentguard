package analysis_test

import (
	"encoding/json"
	"io/fs"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	analysisv1 "github.com/imRYiUK/agentguard/proto/gen/go/agentguard/analysis/v1"

	"github.com/imRYiUK/agentguard/core/analysis"
)

func TestAnalyzeReportsTheImpactMappingVersion(t *testing.T) {
	result, err := analysis.Analyze(analysis.Input{Files: fixtureFiles(t, "version: 1", "version: 1")})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := result.GetImpactMappingVersion(), "2"; got != want {
		t.Errorf("impact mapping version = %q, want %q", got, want)
	}
}

// withPolicy returns the fixture's files with the Statement list of the AWS
// role's policy replaced.
func withPolicy(t *testing.T, statements string) fstest.MapFS {
	t.Helper()
	files := fixtureFiles(t, "version: 1", "version: 1")
	var snap map[string]any
	if err := json.Unmarshal(files["snapshots/aws.json"].Data, &snap); err != nil {
		t.Fatal(err)
	}
	var list any
	if err := json.Unmarshal([]byte(statements), &list); err != nil {
		t.Fatal(err)
	}
	identity := snap["aws"].(map[string]any)["identities"].([]any)[0].(map[string]any)
	doc := identity["policies"].([]any)[0].(map[string]any)["document"].(map[string]any)
	doc["Statement"] = list
	out, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	files["snapshots/aws.json"] = &fstest.MapFile{Data: out}
	return files
}

// impacts lists each Reach Path as "Native Permission => Impact", in the
// order the result gives them.
func impacts(t *testing.T, files fs.FS) []string {
	t.Helper()
	result, err := analysis.Analyze(analysis.Input{Files: files})
	if err != nil {
		t.Fatal(err)
	}
	var out []string
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
		out = append(out, perm+" => "+imp)
	}
	return out
}

func assertImpacts(t *testing.T, got []string, want ...string) {
	t.Helper()
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("Reach Paths differ\n got:\n  %s\nwant:\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}

func TestMappedPermissionsGetOneReachPathPerImpact(t *testing.T) {
	// The fixture's role has s3:* on *, plus two actions no mapping names.
	assertImpacts(t, impacts(t, fixtureFiles(t, "version: 1", "version: 1")),
		"Allow s3:* on * => Read Data",
		"Allow s3:* on * => Modify Data",
		"Allow s3:* on * => Destroy Data",
		"Allow s3:* on * => Exfiltrate",
		"Allow ec2:DescribeInstances on * => unknown",
		"Allow logs:GetLogEvents on * => unknown")
}

func TestUnmappedPermissionShowsImpactUnknown(t *testing.T) {
	files := withPolicy(t, `[{"Effect":"Allow","Action":"ec2:RunInstances","Resource":"arn:aws:ec2:*:*:instance/*"}]`)
	assertImpacts(t, impacts(t, files), "Allow ec2:RunInstances on arn:aws:ec2:*:*:instance/* => unknown")
}

func TestUnknownImpactCitesTheMappingTable(t *testing.T) {
	// Blind Spots would lower the confidence for their own reason, so leave
	// them out and pin the clock, to look at the Impact alone.
	files := withoutBlindSpots(t, withPolicy(t, `[{"Effect":"Allow","Action":"ec2:RunInstances","Resource":"*"}]`))
	result := analyzeAt(t, analysis.Input{Files: files})
	last := result.ReachPaths[0].Links[len(result.ReachPaths[0].Links)-1]
	if last.Kind != analysisv1.LinkKind_LINK_KIND_IMPACT || last.Label != "unknown" {
		t.Fatalf("want an unknown Impact link, got %v", last)
	}
	if got, want := last.Evidence.Source, "agentguard:impact-mappings/v2"; got != want {
		t.Errorf("evidence source = %q, want %q", got, want)
	}
	if result.ReachPaths[0].Confidence != analysisv1.Confidence_CONFIDENCE_HIGH {
		t.Errorf("an unknown Impact does not lower the confidence that the permission is granted, got %v", result.ReachPaths[0].Confidence)
	}
}

func TestAWildcardActionIsMappedNotUnknown(t *testing.T) {
	files := withPolicy(t, `[{"Effect":"Allow","Action":"*","Resource":"*"}]`)
	got := impacts(t, files)
	for _, line := range got {
		if strings.HasSuffix(line, "=> unknown") {
			t.Errorf("a permission that covers mapped actions must not be unknown: %s", line)
		}
	}
	for _, want := range []string{
		"Allow * on * => Read Data",
		"Allow * on * => Destroy Data",
		"Allow * on * => Escalate Privilege",
		"Allow * on * => Modify Identity",
	} {
		if !slices.Contains(got, want) {
			t.Errorf("missing %q in\n  %s", want, strings.Join(got, "\n  "))
		}
	}
}

func TestMappingsOnlyApplyToResourcesOfTheirService(t *testing.T) {
	// Every action on S3 buckets grants S3 Impacts and no IAM Impact.
	files := withPolicy(t, `[{"Effect":"Allow","Action":"*","Resource":"arn:aws:s3:::prod-*"}]`)
	assertImpacts(t, impacts(t, files),
		"Allow * on arn:aws:s3:::prod-* => Read Data",
		"Allow * on arn:aws:s3:::prod-* => Modify Data",
		"Allow * on arn:aws:s3:::prod-* => Destroy Data",
		"Allow * on arn:aws:s3:::prod-* => Exfiltrate")
	// The same on an IAM role grants IAM Impacts and no S3 Impact.
	files = withPolicy(t, `[{"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::123456789012:role/app"}]`)
	assertImpacts(t, impacts(t, files), "Allow iam:PassRole on arn:aws:iam::123456789012:role/app => Escalate Privilege")
}

func TestADenyRemovesTheImpactsOfTheActionsItCovers(t *testing.T) {
	files := withPolicy(t, `[
		{"Effect":"Allow","Action":"s3:*","Resource":"*"},
		{"Effect":"Deny","Action":["s3:Delete*","s3:PutLifecycleConfiguration"],"Resource":"*"}]`)
	assertImpacts(t, impacts(t, files),
		"Allow s3:* on * => Read Data",
		"Allow s3:* on * => Modify Data",
		"Allow s3:* on * => Exfiltrate")
}

func TestADeniedUnmappedPermissionIsNotReported(t *testing.T) {
	files := withPolicy(t, `[
		{"Effect":"Allow","Action":["ec2:RunInstances","s3:GetObject"],"Resource":"*"},
		{"Effect":"Deny","Action":"ec2:*","Resource":"*"}]`)
	assertImpacts(t, impacts(t, files), "Allow s3:GetObject on * => Read Data")
}

func TestAnImpactIsHighConfidenceWhenAnyMappedActionGivesItWithoutDoubt(t *testing.T) {
	// One permission, s3:Get*. A conditional Deny of s3:GetObject makes the
	// grant conditional for that action, but s3:GetObjectVersion gives Read
	// Data with no doubt.
	files := withPolicy(t, `[
		{"Effect":"Allow","Action":"s3:Get*","Resource":"*"},
		{"Effect":"Deny","Action":"s3:GetObject","Resource":"*","Condition":{"Bool":{"aws:SecureTransport":"false"}}}]`)
	// Leave out the Blind Spots and pin the clock, which would lower the
	// confidence for their own reasons.
	result := analyzeAt(t, analysis.Input{Files: withoutBlindSpots(t, files)})
	if len(result.ReachPaths) != 1 {
		t.Fatalf("want one Reach Path, got %v", result.ReachPaths)
	}
	if got := result.ReachPaths[0].Confidence; got != analysisv1.Confidence_CONFIDENCE_HIGH {
		t.Errorf("confidence = %v, want HIGH", got)
	}
}

func TestAConditionalGrantGivesAReducedConfidenceImpact(t *testing.T) {
	files := withPolicy(t, `[{"Effect":"Allow","Action":"s3:DeleteObject","Resource":"*","Condition":{"Bool":{"aws:SecureTransport":"true"}}}]`)
	result, err := analysis.Analyze(analysis.Input{Files: files})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.ReachPaths) != 1 || result.ReachPaths[0].Confidence != analysisv1.Confidence_CONFIDENCE_REDUCED {
		t.Errorf("want one REDUCED Reach Path, got %v", result.ReachPaths)
	}
}
