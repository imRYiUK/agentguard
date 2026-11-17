// Package awspolicy reads AWS identity-based policy documents into Native
// Permissions.
//
// Semantics are deliberately minimal for now: only Allow statements with
// Action and Resource and no Condition produce grants. Deny, NotAction,
// NotResource, and conditioned statements are skipped.
package awspolicy

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/imRYiUK/agentguard/core/internal/limits"
)

// Grant is one Native Permission: an action allowed on a resource, exactly
// as the policy states them.
type Grant struct {
	Action   string
	Resource string
	// Location is the JSONPath of the granting statement, relative to the
	// policy document.
	Location string
}

type document struct {
	Statement statements `json:"Statement"`
}

type statement struct {
	Effect      string          `json:"Effect"`
	Action      stringOrList    `json:"Action"`
	NotAction   json.RawMessage `json:"NotAction"`
	Resource    stringOrList    `json:"Resource"`
	NotResource json.RawMessage `json:"NotResource"`
	Condition   json.RawMessage `json:"Condition"`
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

type stringOrList []string

func (s *stringOrList) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		var one string
		if err := json.Unmarshal(b, &one); err != nil {
			return err
		}
		*s = []string{one}
		return nil
	}
	if err := json.Unmarshal(b, (*[]string)(s)); err != nil {
		return errors.New("Action and Resource must be a string or a list of strings")
	}
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

// Grants returns the Native Permissions a policy document allows, in
// statement order.
func Grants(doc *structpb.Struct) ([]Grant, error) {
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
	var grants []Grant
	for i, st := range d.Statement.list {
		if st.Effect != "Allow" || st.NotAction != nil || st.NotResource != nil || st.Condition != nil {
			continue
		}
		location := fmt.Sprintf("$.Statement[%d]", i)
		if d.Statement.single {
			location = "$.Statement"
		}
		for _, a := range st.Action {
			for _, r := range st.Resource {
				grants = append(grants, Grant{Action: a, Resource: r, Location: location})
			}
		}
	}
	return grants, nil
}
