package awspolicy_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/imRYiUK/agentguard/core/internal/awspolicy"
	"github.com/imRYiUK/agentguard/core/internal/limits"
)

// statements parses policy documents and returns their statements together,
// as one Identity's policies are evaluated together. Each statement's Policy
// is the index of its document.
func statements(t *testing.T, docs ...string) []awspolicy.Statement {
	t.Helper()
	var all []awspolicy.Statement
	for i, d := range docs {
		var doc structpb.Struct
		if err := protojson.Unmarshal([]byte(d), &doc); err != nil {
			t.Fatalf("document %d is not a JSON object: %v", i, err)
		}
		stmts, err := awspolicy.Parse(&doc)
		if err != nil {
			t.Fatalf("document %d: %v", i, err)
		}
		for j := range stmts {
			stmts[j].Policy = i
		}
		all = append(all, stmts...)
	}
	return all
}

// describe renders a Grant on one line, for comparing against a literal.
func describe(g awspolicy.Grant) string {
	action := g.Action
	if len(g.Statement.NotActions) > 0 {
		action = "all except " + strings.Join(g.Statement.NotActions, ",")
	}
	resource := g.Resource
	if len(g.Statement.NotResources) > 0 {
		resource = "all except " + strings.Join(g.Statement.NotResources, ",")
	}
	out := fmt.Sprintf("%s on %s", action, resource)
	if g.Conditional {
		out += " [conditional]"
	}
	return out
}

// evaluate returns the described Grants of an action under the documents.
func evaluate(t *testing.T, action string, docs ...string) []string {
	t.Helper()
	grants, err := awspolicy.Evaluate(statements(t, docs...), action, nil)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, g := range grants {
		out = append(out, describe(g))
	}
	return out
}

func allow(action, resource string) string {
	return fmt.Sprintf(`{"Statement":[{"Effect":"Allow","Action":%s,"Resource":%s}]}`, jsonList(action), jsonList(resource))
}

func deny(action, resource string) string {
	return fmt.Sprintf(`{"Statement":[{"Effect":"Deny","Action":%s,"Resource":%s}]}`, jsonList(action), jsonList(resource))
}

// jsonList renders comma-separated entries as a JSON list.
func jsonList(entries string) string {
	parts := strings.Split(entries, ",")
	for i, p := range parts {
		parts[i] = fmt.Sprintf("%q", p)
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func assertGrants(t *testing.T, got []string, want ...string) {
	t.Helper()
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("grants differ\n got: %q\nwant: %q", got, want)
	}
}

func TestAllowGrantsTheActionOnItsResources(t *testing.T) {
	assertGrants(t, evaluate(t, "s3:*", allow("s3:*", "*")), "s3:* on *")
	assertGrants(t, evaluate(t, "s3:*", allow("s3:*", "arn:aws:s3:::a,arn:aws:s3:::b")),
		"s3:* on arn:aws:s3:::a", "s3:* on arn:aws:s3:::b")
	// A single statement object is as valid as a list of them.
	assertGrants(t, evaluate(t, "s3:*", `{"Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}}`), "s3:* on *")
}

func TestAllowOfOtherActionsGrantsNothing(t *testing.T) {
	assertGrants(t, evaluate(t, "s3:*", allow("s3:GetObject,s3:List*", "*")))
	assertGrants(t, evaluate(t, "s3:*", allow("ec2:*", "*")))
}

func TestExplicitDenyOverridesAllow(t *testing.T) {
	t.Run("in the same policy", func(t *testing.T) {
		doc := `{"Statement":[
			{"Effect":"Allow","Action":"s3:*","Resource":"*"},
			{"Effect":"Deny","Action":"s3:*","Resource":"*"}]}`
		assertGrants(t, evaluate(t, "s3:*", doc))
	})
	t.Run("in another policy, whatever the order", func(t *testing.T) {
		assertGrants(t, evaluate(t, "s3:*", allow("s3:*", "*"), deny("s3:*", "*")))
		assertGrants(t, evaluate(t, "s3:*", deny("s3:*", "*"), allow("s3:*", "*")))
	})
	t.Run("by a broader action", func(t *testing.T) {
		assertGrants(t, evaluate(t, "s3:DeleteBucket", allow("s3:DeleteBucket", "*"), deny("s3:*", "*")))
		assertGrants(t, evaluate(t, "s3:DeleteBucket", allow("s3:DeleteBucket", "*"), deny("*", "*")))
	})
	t.Run("on only some of the resources", func(t *testing.T) {
		assertGrants(t, evaluate(t, "s3:*", allow("s3:*", "arn:aws:s3:::a,arn:aws:s3:::b"), deny("s3:*", "arn:aws:s3:::b")),
			"s3:* on arn:aws:s3:::a")
	})
}

func TestDenyThatDoesNotCoverTheGrantLeavesIt(t *testing.T) {
	// A narrower action leaves the rest of the grant, so it is kept.
	assertGrants(t, evaluate(t, "s3:*", allow("s3:*", "*"), deny("s3:DeleteBucket", "*")), "s3:* on *")
	// A narrower resource leaves the rest of the resources.
	assertGrants(t, evaluate(t, "s3:*", allow("s3:*", "*"), deny("s3:*", "arn:aws:s3:::audit-logs/*")), "s3:* on *")
	assertGrants(t, evaluate(t, "s3:*", allow("s3:*", "arn:aws:s3:::prod-*"), deny("s3:*", "arn:aws:s3:::prod-logs/*")),
		"s3:* on arn:aws:s3:::prod-*")
	// A deny of another action is no deny of this one.
	assertGrants(t, evaluate(t, "s3:*", allow("s3:*", "*"), deny("iam:*", "*")), "s3:* on *")
}

func TestActionWildcards(t *testing.T) {
	tests := []struct {
		name, allowed, action string
		want                  bool
	}{
		{"star covers everything", "*", "s3:DeleteBucket", true},
		{"service star", "s3:*", "s3:DeleteBucket", true},
		{"prefix star", "s3:Delete*", "s3:DeleteBucket", true},
		{"prefix star misses other actions", "s3:Delete*", "s3:GetObject", false},
		{"star inside", "s3:*Bucket", "s3:DeleteBucket", true},
		{"question mark is one character", "s3:Get?bject", "s3:GetObject", true},
		{"question mark is not zero characters", "s3:GetObject?", "s3:GetObject", false},
		{"action names are case-insensitive", "S3:deletebucket", "s3:DeleteBucket", true},
		{"wildcard in the action asked about needs a wildcard to cover it", "s3:Get*", "s3:*", false},
		{"question mark does not cover a star", "s3:?", "s3:*", false},
		{"star covers a star", "s3:*", "s3:*", true},
		{"service differs", "s3-object-lambda:*", "s3:GetObject", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := evaluate(t, tc.action, allow(tc.allowed, "*"))
			if (len(got) > 0) != tc.want {
				t.Errorf("Allow %q for %q: got grants %q, want a grant: %v", tc.allowed, tc.action, got, tc.want)
			}
		})
	}
}

func TestResourceWildcardsInADeny(t *testing.T) {
	tests := []struct {
		name, allowed, denied string
		removed               bool
	}{
		{"same pattern", "arn:aws:s3:::prod-*", "arn:aws:s3:::prod-*", true},
		{"star", "arn:aws:s3:::prod-*", "*", true},
		{"broader prefix", "arn:aws:s3:::prod-logs/*", "arn:aws:s3:::prod-*", true},
		{"service-wide star", "arn:aws:s3:::prod-*", "arn:aws:s3:::*", true},
		{"literal resource", "arn:aws:s3:::prod-logs", "arn:aws:s3:::prod-*", true},
		{"narrower deny", "arn:aws:s3:::prod-*", "arn:aws:s3:::prod-logs", false},
		{"question mark does not cover a star", "arn:aws:s3:::b*", "arn:aws:s3:::b?", false},
		{"question mark covers a question mark", "arn:aws:s3:::b?", "arn:aws:s3:::b?", true},
		{"star covers a question mark", "arn:aws:s3:::b?", "arn:aws:s3:::b*", true},
		{"resources are case-sensitive", "arn:aws:s3:::prod-*", "ARN:AWS:S3:::PROD-*", false},
		{"another service", "arn:aws:s3:::prod-*", "arn:aws:ec2:*", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := evaluate(t, "s3:*", allow("s3:*", tc.allowed), deny("s3:*", tc.denied))
			if removed := len(got) == 0; removed != tc.removed {
				t.Errorf("Allow on %q, Deny on %q: got grants %q, want the grant removed: %v", tc.allowed, tc.denied, got, tc.removed)
			}
		})
	}
}

func TestGrantNamesTheStatementAndActionPatternThatGrantedIt(t *testing.T) {
	stmts := statements(t,
		`{"Statement":[{"Effect":"Allow","Action":"ec2:*","Resource":"*"}]}`,
		`{"Statement":[{"Effect":"Allow","Action":["ec2:*","s3:Get*","*"],"Resource":"*"}]}`)
	grants, err := awspolicy.Evaluate(stmts, "s3:GetObject", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 1 {
		t.Fatalf("want one grant, got %d", len(grants))
	}
	g := grants[0]
	if g.Statement.Policy != 1 || g.Statement.Location != "$.Statement[0]" || g.Action != "s3:Get*" {
		t.Errorf("got policy %d, location %q, action %q; want policy 1, location $.Statement[0], action s3:Get*",
			g.Statement.Policy, g.Statement.Location, g.Action)
	}
}

func TestSingleStatementObjectHasItsOwnLocation(t *testing.T) {
	stmts := statements(t, `{"Statement":{"Effect":"Allow","Action":"s3:*","Resource":"*"}}`)
	if stmts[0].Location != "$.Statement" {
		t.Errorf("got location %q, want $.Statement", stmts[0].Location)
	}
}

// statement renders a one-statement policy document from the statement's
// JSON fields.
func statement(fields string) string {
	return `{"Statement":[{` + fields + `}]}`
}

func TestNotActionInAnAllowGrantsEverythingButTheListedActions(t *testing.T) {
	notAction := func(actions string) string {
		return statement(`"Effect":"Allow","NotAction":` + jsonList(actions) + `,"Resource":"*"`)
	}
	tests := []struct {
		name, notAction, action string
		want                    []string
	}{
		{"another service", "iam:*", "s3:*", []string{"all except iam:* on *"}},
		{"a concrete action of another service", "iam:*,sts:*", "s3:DeleteBucket", []string{"all except iam:*,sts:* on *"}},
		{"the service itself", "s3:*", "s3:*", nil},
		{"a concrete action the list covers", "s3:*", "s3:DeleteBucket", nil},
		{"a concrete action the list names", "S3:DELETEBUCKET", "s3:DeleteBucket", nil},
		{"a concrete action the list leaves out", "s3:Get*", "s3:DeleteBucket", []string{"all except s3:Get* on *"}},
		// The action asked about stands for every S3 action, and the list
		// leaves some of them out, so the grant stays.
		{"part of the actions asked about", "s3:Get*", "s3:*", []string{"all except s3:Get* on *"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertGrants(t, evaluate(t, tc.action, notAction(tc.notAction)), tc.want...)
		})
	}
}

func TestNotResourceInAnAllowGrantsEveryResourceButTheListedOnes(t *testing.T) {
	doc := statement(`"Effect":"Allow","Action":"s3:*","NotResource":["arn:aws:s3:::audit","arn:aws:s3:::audit/*"]`)
	assertGrants(t, evaluate(t, "s3:*", doc), "s3:* on all except arn:aws:s3:::audit,arn:aws:s3:::audit/*")
}

func TestDenyWithNotActionDeniesEverythingButTheListedActions(t *testing.T) {
	// "Deny everything except reads": only reads can be allowed.
	denyAllButReads := statement(`"Effect":"Deny","NotAction":["s3:Get*","s3:List*"],"Resource":"*"`)
	assertGrants(t, evaluate(t, "s3:DeleteBucket", allow("s3:*", "*"), denyAllButReads))
	assertGrants(t, evaluate(t, "s3:GetObject", allow("s3:*", "*"), denyAllButReads), "s3:* on *")
	// The action asked about stands for every S3 action, some of which the
	// Deny leaves allowed, so the grant stays.
	assertGrants(t, evaluate(t, "s3:*", allow("s3:*", "*"), denyAllButReads), "s3:* on *")
}

func TestDenyWithNotResourceDeniesEveryResourceButTheListedOnes(t *testing.T) {
	denyOutsideDev := statement(`"Effect":"Deny","Action":"s3:*","NotResource":["arn:aws:s3:::dev","arn:aws:s3:::dev/*"]`)
	tests := []struct {
		name, resource string
		want           []string
	}{
		{"a resource outside the list", "arn:aws:s3:::prod", nil},
		{"a resource the list names", "arn:aws:s3:::dev", []string{"s3:* on arn:aws:s3:::dev"}},
		{"a resource the list covers", "arn:aws:s3:::dev/key", []string{"s3:* on arn:aws:s3:::dev/key"}},
		// The pattern may include resources the Deny leaves allowed, so the
		// grant stays.
		{"a pattern that is not provably outside the list", "arn:aws:s3:::*", []string{"s3:* on arn:aws:s3:::*"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertGrants(t, evaluate(t, "s3:*", allow("s3:*", tc.resource), denyOutsideDev), tc.want...)
		})
	}
}

func TestDenyOfAllowWithNotResource(t *testing.T) {
	allowAllButAudit := statement(`"Effect":"Allow","Action":"s3:*","NotResource":["arn:aws:s3:::audit","arn:aws:s3:::audit/*"]`)
	const grant = "s3:* on all except arn:aws:s3:::audit,arn:aws:s3:::audit/*"
	t.Run("a Deny of every resource", func(t *testing.T) {
		assertGrants(t, evaluate(t, "s3:*", allowAllButAudit, deny("s3:*", "*")))
	})
	t.Run("a Deny of some resources", func(t *testing.T) {
		assertGrants(t, evaluate(t, "s3:*", allowAllButAudit, deny("s3:*", "arn:aws:s3:::prod-*")), grant)
	})
	t.Run("a Deny of everything but a subset of the excluded resources", func(t *testing.T) {
		// Everything outside audit is already not granted; the Deny leaves
		// audit allowed, which the grant never included, so it covers all.
		denyOutsideAudit := statement(`"Effect":"Deny","Action":"s3:*","NotResource":["arn:aws:s3:::audit","arn:aws:s3:::audit/*"]`)
		assertGrants(t, evaluate(t, "s3:*", allowAllButAudit, denyOutsideAudit))
	})
	t.Run("a Deny that leaves alone a resource the grant includes", func(t *testing.T) {
		denyOutsideAuditAndDev := statement(`"Effect":"Deny","Action":"s3:*","NotResource":["arn:aws:s3:::audit","arn:aws:s3:::dev"]`)
		assertGrants(t, evaluate(t, "s3:*", allowAllButAudit, denyOutsideAuditAndDev), grant)
	})
}

func TestConditionedAllowIsAConditionalGrant(t *testing.T) {
	doc := statement(`"Effect":"Allow","Action":"s3:*","Resource":"*","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}`)
	grants, err := awspolicy.Evaluate(statements(t, doc), "s3:*", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 1 || !grants[0].Conditional || grants[0].Reason == "" {
		t.Fatalf("want one conditional grant with a reason, got %+v", grants)
	}
}

func TestEmptyConditionRestrictsNothing(t *testing.T) {
	for _, condition := range []string{`{}`, `null`} {
		doc := statement(`"Effect":"Allow","Action":"s3:*","Resource":"*","Condition":` + condition)
		assertGrants(t, evaluate(t, "s3:*", doc), "s3:* on *")
	}
}

func TestConditionedDenyMakesTheGrantConditional(t *testing.T) {
	denyOffHours := statement(`"Effect":"Deny","Action":"s3:*","Resource":"*","Condition":{"DateGreaterThan":{"aws:CurrentTime":"2026-01-01T00:00:00Z"}}`)
	t.Run("when it covers the grant", func(t *testing.T) {
		assertGrants(t, evaluate(t, "s3:*", allow("s3:*", "*"), denyOffHours), "s3:* on * [conditional]")
		grants, _ := awspolicy.Evaluate(statements(t, allow("s3:*", "*"), denyOffHours), "s3:*", nil)
		if grants[0].Reason == "" {
			t.Error("a conditional grant must say why")
		}
	})
	t.Run("not when it covers another resource", func(t *testing.T) {
		assertGrants(t, evaluate(t, "s3:*", allow("s3:*", "arn:aws:s3:::a"), statement(`"Effect":"Deny","Action":"s3:*","Resource":"arn:aws:s3:::b","Condition":{"Bool":{"k":"true"}}`)),
			"s3:* on arn:aws:s3:::a")
	})
	t.Run("an unconditional Deny still removes the grant", func(t *testing.T) {
		assertGrants(t, evaluate(t, "s3:*", allow("s3:*", "*"), denyOffHours, deny("s3:*", "*")))
		assertGrants(t, evaluate(t, "s3:*", allow("s3:*", "*"), deny("s3:*", "*"), denyOffHours))
	})
}

func TestUnconditionalDenyRemovesAConditionalGrant(t *testing.T) {
	doc := statement(`"Effect":"Allow","Action":"s3:*","Resource":"*","Condition":{"Bool":{"k":"true"}}`)
	assertGrants(t, evaluate(t, "s3:*", doc, deny("s3:*", "*")))
}

func TestParseRejectsInvalidStatements(t *testing.T) {
	tests := []struct {
		name, fields, want string
	}{
		{"no Effect", `"Action":"s3:*","Resource":"*"`, `Statement[0]: Effect must be "Allow" or "Deny"`},
		{"unknown Effect", `"Effect":"Permit","Action":"s3:*","Resource":"*"`, `Statement[0]: Effect must be "Allow" or "Deny"`},
		{"Effect is case-sensitive", `"Effect":"allow","Action":"s3:*","Resource":"*"`, `Statement[0]: Effect must be "Allow" or "Deny"`},
		{"no Action", `"Effect":"Allow","Resource":"*"`, "Statement[0]: needs Action or NotAction"},
		{"empty Action", `"Effect":"Allow","Action":[],"Resource":"*"`, "Statement[0]: needs Action or NotAction"},
		{"Action and NotAction", `"Effect":"Allow","Action":"s3:*","NotAction":"iam:*","Resource":"*"`, "Statement[0]: Action and NotAction cannot both be present"},
		{"no Resource", `"Effect":"Allow","Action":"s3:*"`, "Statement[0]: needs Resource or NotResource"},
		{"Resource and NotResource", `"Effect":"Allow","Action":"s3:*","Resource":"*","NotResource":"x"`, "Statement[0]: Resource and NotResource cannot both be present"},
		{"Condition is a list", `"Effect":"Allow","Action":"s3:*","Resource":"*","Condition":[]`, "Condition must be an object"},
		{"Action entry too long", `"Effect":"Allow","Action":"` + strings.Repeat("a", limits.MaxPolicyEntryLength+1) + `","Resource":"*"`,
			fmt.Sprintf("Statement[0]: an Action entry is longer than %d characters", limits.MaxPolicyEntryLength)},
		{"Resource entry too long", `"Effect":"Allow","Action":"s3:*","NotResource":["` + strings.Repeat("a", limits.MaxPolicyEntryLength+1) + `"]`,
			fmt.Sprintf("Statement[0]: a NotResource entry is longer than %d characters", limits.MaxPolicyEntryLength)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var doc structpb.Struct
			if err := protojson.Unmarshal([]byte(statement(tc.fields)), &doc); err != nil {
				t.Fatal(err)
			}
			_, err := awspolicy.Parse(&doc)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("want an error containing %q, got %v", tc.want, err)
			}
			if err != nil && strings.Contains(err.Error(), strings.Repeat("a", 100)) {
				t.Errorf("the error echoes the policy's text: %.200s", err)
			}
		})
	}
}

func TestParseLocatesErrorsInASingleStatement(t *testing.T) {
	var doc structpb.Struct
	if err := protojson.Unmarshal([]byte(`{"Statement":{"Effect":"Permit","Action":"a:b","Resource":"*"}}`), &doc); err != nil {
		t.Fatal(err)
	}
	if _, err := awspolicy.Parse(&doc); err == nil || !strings.Contains(err.Error(), `Statement: Effect must be "Allow" or "Deny"`) {
		t.Errorf("want an error at Statement, got %v", err)
	}
}

func TestParseRejectsTooManyEntries(t *testing.T) {
	entries := make([]string, limits.MaxPolicyEntries+1)
	for i := range entries {
		entries[i] = fmt.Sprintf("%q", fmt.Sprintf("s3:Action%d", i))
	}
	var doc structpb.Struct
	content := `{"Statement":[{"Effect":"Allow","Action":[` + strings.Join(entries, ",") + `],"Resource":"*"}]}`
	if err := protojson.Unmarshal([]byte(content), &doc); err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("has more than %d Action, NotAction, Resource, and NotResource entries", limits.MaxPolicyEntries)
	if _, err := awspolicy.Parse(&doc); err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("want an error containing %q, got %v", want, err)
	}
}

func TestEvaluateStopsWhenItsBudgetIsGone(t *testing.T) {
	stmts := statements(t, allow("s3:*", "*"), deny("s3:*", "arn:aws:s3:::a"))
	_, err := awspolicy.Evaluate(stmts, "s3:*", awspolicy.NewBudget(3))
	if !errors.Is(err, awspolicy.ErrBudgetExhausted) {
		t.Errorf("want ErrBudgetExhausted, got %v", err)
	}
}

// Patterns built to make matching as slow as possible must not run for long:
// the work they can cause is bounded by the budget.
func TestHostilePatternsCannotRunAwayWithTheCPU(t *testing.T) {
	hostile := strings.Repeat("*a", limits.MaxPolicyEntryLength/2-1) + "b"
	subject := strings.Repeat("a", limits.MaxPolicyEntryLength)
	docs := []string{allow("s3:*", subject)}
	for i := 0; i < 50; i++ {
		docs = append(docs, deny("s3:*", hostile))
	}
	start := time.Now()
	_, err := awspolicy.Evaluate(statements(t, docs...), "s3:*", awspolicy.NewBudget(limits.MaxPolicyEvalSteps))
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Errorf("evaluation ran for %v", elapsed)
	}
	if err != nil && !errors.Is(err, awspolicy.ErrBudgetExhausted) {
		t.Errorf("unexpected error: %v", err)
	}
}

// permissions returns the described Native Permissions the documents grant.
func permissions(t *testing.T, docs ...string) []string {
	t.Helper()
	grants, err := awspolicy.Permissions(statements(t, docs...), nil)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, g := range grants {
		out = append(out, describe(g))
	}
	return out
}

func TestPermissionsListsEveryActionAndResourceAnAllowGrants(t *testing.T) {
	assertGrants(t, permissions(t, allow("s3:GetObject,ec2:RunInstances", "arn:aws:s3:::a,arn:aws:s3:::b")),
		"s3:GetObject on arn:aws:s3:::a", "s3:GetObject on arn:aws:s3:::b",
		"ec2:RunInstances on arn:aws:s3:::a", "ec2:RunInstances on arn:aws:s3:::b")
	assertGrants(t, permissions(t, allow("*", "*"), allow("iam:PassRole", "*")), "* on *", "iam:PassRole on *")
}

func TestPermissionsLeavesOutWhatADenyRemoves(t *testing.T) {
	assertGrants(t, permissions(t, allow("s3:GetObject,s3:PutObject", "*"), deny("s3:PutObject", "*")), "s3:GetObject on *")
	assertGrants(t, permissions(t, allow("s3:*", "*"), deny("*", "*")))
	// A Deny of only part of the permission leaves it in place.
	assertGrants(t, permissions(t, allow("s3:*", "*"), deny("s3:DeleteBucket", "*")), "s3:* on *")
	assertGrants(t, permissions(t, allow("s3:*", "*"), deny("s3:*", "arn:aws:s3:::audit")), "s3:* on *")
}

func TestPermissionsOfANotActionAllowIsOneWholePermission(t *testing.T) {
	doc := statement(`"Effect":"Allow","NotAction":["iam:*"],"Resource":"*"`)
	assertGrants(t, permissions(t, doc), "all except iam:* on *")
	assertGrants(t, permissions(t, doc, deny("*", "*")))
	assertGrants(t, permissions(t, doc, deny("s3:*", "*")), "all except iam:* on *")
}

func TestPermissionsMarksConditionalGrants(t *testing.T) {
	cond := statement(`"Effect":"Allow","Action":"ec2:RunInstances","Resource":"*","Condition":{"Bool":{"aws:SecureTransport":"true"}}`)
	assertGrants(t, permissions(t, cond), "ec2:RunInstances on * [conditional]")
	condDeny := statement(`"Effect":"Deny","Action":"ec2:*","Resource":"*","Condition":{"Bool":{"aws:SecureTransport":"false"}}`)
	assertGrants(t, permissions(t, allow("ec2:RunInstances", "*"), condDeny), "ec2:RunInstances on * [conditional]")
}

func TestPermissionsStopsWhenItsBudgetIsGone(t *testing.T) {
	_, err := awspolicy.Permissions(statements(t, allow("s3:*", "*"), deny("s3:*", "arn:aws:s3:::a")), awspolicy.NewBudget(1))
	if !errors.Is(err, awspolicy.ErrBudgetExhausted) {
		t.Errorf("want ErrBudgetExhausted, got %v", err)
	}
}

func TestResourceInService(t *testing.T) {
	tests := []struct {
		resource, service string
		want              bool
	}{
		{"*", "s3", true},
		{"*", "iam", true},
		{"arn:aws:s3:::prod-*", "s3", true},
		{"arn:aws:s3:::prod-*", "iam", false},
		{"arn:aws:s3:::prod-bucket/*", "s3", true},
		{"arn:aws:iam::123456789012:role/ops", "iam", true},
		{"arn:aws:iam::123456789012:role/ops", "s3", false},
		{"arn:aws:*:::x", "s3", true},
		{"arn:aws:s3*:::x", "s3", true},
		{"arn:aws:i?m::123456789012:role/ops", "iam", true},
		{"arn:aws:i?m::123456789012:role/ops", "s3", false},
		{"arn:*", "s3", true},
		{"arn:aws*", "iam", true},
		{"*:s3:::x", "iam", true},
		{"a*", "iam", true},
		{"arn:aws-cn:s3:::x", "s3", true},
		// The ARN of a resource of no service at all.
		{"prod-bucket", "s3", false},
		{"arn:aws:s3", "s3", false},
		// A NotResource grant stands for every resource but some.
		{"", "s3", true},
		{"", "iam", true},
		// IAM compares service names without regard to case.
		{"arn:aws:S3:::x", "s3", true},
	}
	for _, tc := range tests {
		if got := awspolicy.ResourceInService(tc.resource, tc.service, nil); got != tc.want {
			t.Errorf("ResourceInService(%q, %q) = %v, want %v", tc.resource, tc.service, got, tc.want)
		}
	}
}

func TestStatementWildcard(t *testing.T) {
	tests := []struct {
		name, doc string
		want      bool
	}{
		{"every action", allow("*", "arn:aws:s3:::a"), true},
		{"a service's actions on every resource", allow("s3:*", "*"), true},
		{"a service's actions among others", allow("s3:GetObject,iam:*", "*"), true},
		{"a service's actions on a named resource", allow("s3:*", "arn:aws:s3:::a"), false},
		{"named actions on every resource", allow("s3:Get*,s3:List*", "*"), false},
		{"a Deny", deny("*", "*"), false},
		{"every action but some", statement(`"Effect":"Allow","NotAction":["iam:*"],"Resource":"*"`), false},
		{"a service's actions on every resource but some", statement(`"Effect":"Allow","Action":"s3:*","NotResource":["arn:aws:s3:::a"]`), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stmts := statements(t, tc.doc)
			if got := stmts[0].Wildcard(); got != tc.want {
				t.Errorf("Wildcard() = %v, want %v", got, tc.want)
			}
		})
	}
}
