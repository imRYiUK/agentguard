// Package awspolicy reads AWS identity-based policy documents and works out
// which Native Permissions they grant an Identity.
//
// Parse turns a policy document into Statements. Evaluate takes all the
// Statements that apply to one Identity, from every managed, inline, and
// group-attached policy, and returns the Grants of one action: the Allow
// statements that cover it, minus the resources an explicit Deny covers.
//
// Matching follows IAM: action names are case-insensitive and resource ARNs
// are case-sensitive, and the only wildcards are * (any run of characters)
// and ? (one character). A Condition is never evaluated. A Grant that depends
// on one is marked Conditional.
//
// The evaluation is deliberately conservative: it may report a grant that a
// precise evaluation would remove, and never the reverse. A Deny removes a
// Grant only when it provably covers all of it. A Deny that covers only part
// of a Grant leaves the whole Grant in place.
package awspolicy

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/imRYiUK/agentguard/core/internal/limits"
)

// Effect is whether a statement allows or denies.
type Effect string

// The two effects a statement can have.
const (
	Allow Effect = "Allow"
	Deny  Effect = "Deny"
)

// Statement is one statement of a policy document.
type Statement struct {
	Effect Effect
	// Actions and NotActions are the statement's Action and NotAction
	// entries. At most one is set.
	Actions    []string
	NotActions []string
	// Resources and NotResources are the statement's Resource and
	// NotResource entries. At most one is set.
	Resources    []string
	NotResources []string
	// Conditional is true when the statement has a Condition, which is not
	// evaluated.
	Conditional bool
	// Location is the JSONPath of the statement, relative to the policy
	// document.
	Location string
	// Policy identifies the policy the statement came from. Parse leaves it
	// zero. The caller sets it to tell apart the policies it evaluates
	// together.
	Policy int
}

// Wildcard reports whether the statement is a wildcard policy: an Allow of
// every action, or of every action of a service on every resource. A
// statement that allows by NotAction is not one, though it can grant as much.
func (s *Statement) Wildcard() bool {
	if s.Effect != Allow || len(s.NotActions) > 0 {
		return false
	}
	for _, action := range s.Actions {
		if action == "*" || (strings.HasSuffix(action, ":*") && slices.Contains(s.Resources, "*")) {
			return true
		}
	}
	return false
}

type document struct {
	Statement statements `json:"Statement"`
}

type statement struct {
	Effect      string       `json:"Effect"`
	Action      stringOrList `json:"Action"`
	NotAction   stringOrList `json:"NotAction"`
	Resource    stringOrList `json:"Resource"`
	NotResource stringOrList `json:"NotResource"`
	Condition   conditions   `json:"Condition"`
}

// statements accepts both a single statement object and a list of them, as
// IAM does. single records which form was used, for locations.
type statements struct {
	list   []statement
	single bool
}

func (s *statements) UnmarshalJSON(b []byte) error {
	switch {
	case len(b) > 0 && b[0] == '{':
		s.single = true
		s.list = make([]statement, 1)
		return json.Unmarshal(b, &s.list[0])
	case len(b) > 0 && b[0] == '[':
		return json.Unmarshal(b, &s.list)
	case string(b) == "null":
		return nil
	}
	return errors.New("Statement must be a statement or a list of statements")
}

// stringOrList is a JSON string or list of strings. set records that the key
// was present, so that an empty list can be told from an absent key.
type stringOrList struct {
	entries []string
	set     bool
}

func (s *stringOrList) UnmarshalJSON(b []byte) error {
	s.set = string(b) != "null"
	if len(b) > 0 && b[0] == '"' {
		var one string
		if err := json.Unmarshal(b, &one); err != nil {
			return err
		}
		s.entries = []string{one}
		return nil
	}
	if err := json.Unmarshal(b, &s.entries); err != nil {
		return errors.New("Action and Resource must be a string or a list of strings")
	}
	return nil
}

// conditions records whether a Condition block names any condition. A null or
// empty block restricts nothing.
type conditions bool

func (c *conditions) UnmarshalJSON(b []byte) error {
	var block map[string]json.RawMessage
	if err := json.Unmarshal(b, &block); err != nil {
		return errors.New("Condition must be an object")
	}
	*c = len(block) > 0
	return nil
}

// deeper reports whether v nests more than limits.MaxPolicyDepth levels of
// objects and lists.
func deeper(v *structpb.Value, depth int) bool {
	var children []*structpb.Value
	switch k := v.GetKind().(type) {
	case *structpb.Value_StructValue:
		for _, c := range k.StructValue.GetFields() {
			children = append(children, c)
		}
	case *structpb.Value_ListValue:
		children = k.ListValue.GetValues()
	default:
		return false
	}
	depth++
	if depth > limits.MaxPolicyDepth {
		return true
	}
	for _, c := range children {
		if deeper(c, depth) {
			return true
		}
	}
	return false
}

// Parse reads the statements of a policy document, in document order.
func Parse(doc *structpb.Struct) ([]Statement, error) {
	if proto.Size(doc) > limits.MaxPolicyDocumentBytes {
		return nil, fmt.Errorf("IAM policy document is too large (the limit is %d bytes)", limits.MaxPolicyDocumentBytes)
	}
	if deeper(structpb.NewStructValue(doc), 0) {
		return nil, fmt.Errorf("IAM policy document is nested deeper than the limit of %d levels", limits.MaxPolicyDepth)
	}
	raw, err := json.Marshal(doc.AsMap())
	if err != nil {
		return nil, err
	}
	var d document
	if err := json.Unmarshal(raw, &d); err != nil {
		var typeErr *json.UnmarshalTypeError
		if errors.As(err, &typeErr) {
			field := typeErr.Field[strings.LastIndex(typeErr.Field, ".")+1:]
			article := "a"
			if typeErr.Value == "array" || typeErr.Value == "object" {
				article = "an"
			}
			return nil, fmt.Errorf("invalid policy document: %s must not be %s %s", field, article, typeErr.Value)
		}
		return nil, fmt.Errorf("invalid policy document: %w", err)
	}
	entries := 0
	for _, st := range d.Statement.list {
		entries += len(st.Action.entries) + len(st.NotAction.entries) + len(st.Resource.entries) + len(st.NotResource.entries)
	}
	if entries > limits.MaxPolicyEntries {
		return nil, fmt.Errorf("invalid policy document: has more than %d Action, NotAction, Resource, and NotResource entries", limits.MaxPolicyEntries)
	}
	var out []Statement
	for i, st := range d.Statement.list {
		location := fmt.Sprintf("$.Statement[%d]", i)
		name := fmt.Sprintf("Statement[%d]", i)
		if d.Statement.single {
			location, name = "$.Statement", "Statement"
		}
		if err := check(st); err != nil {
			return nil, fmt.Errorf("invalid policy document: %s: %w", name, err)
		}
		out = append(out, Statement{
			Effect:       Effect(st.Effect),
			Actions:      st.Action.entries,
			NotActions:   st.NotAction.entries,
			Resources:    st.Resource.entries,
			NotResources: st.NotResource.entries,
			Conditional:  bool(st.Condition),
			Location:     location,
		})
	}
	return out, nil
}

// check reports whether a statement has the shape IAM requires of an
// identity-based policy: an Effect, one of Action and NotAction, and one of
// Resource and NotResource, with entries of a sane length. Errors name the
// problem and never quote the policy.
func check(st statement) error {
	if st.Effect != string(Allow) && st.Effect != string(Deny) {
		return errors.New(`Effect must be "Allow" or "Deny"`)
	}
	if st.Action.set && st.NotAction.set {
		return errors.New("Action and NotAction cannot both be present")
	}
	if len(st.Action.entries) == 0 && len(st.NotAction.entries) == 0 {
		return errors.New("needs Action or NotAction")
	}
	if st.Resource.set && st.NotResource.set {
		return errors.New("Resource and NotResource cannot both be present")
	}
	if len(st.Resource.entries) == 0 && len(st.NotResource.entries) == 0 {
		return errors.New("needs Resource or NotResource")
	}
	for _, field := range []struct {
		name    string // with its article, for the message
		entries []string
	}{
		{"an Action", st.Action.entries}, {"a NotAction", st.NotAction.entries},
		{"a Resource", st.Resource.entries}, {"a NotResource", st.NotResource.entries},
	} {
		for _, e := range field.entries {
			if len(e) > limits.MaxPolicyEntryLength {
				return fmt.Errorf("%s entry is longer than %d characters", field.name, limits.MaxPolicyEntryLength)
			}
		}
	}
	return nil
}
