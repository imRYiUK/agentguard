// Package impact attaches Impacts to Native Permissions through a versioned
// mapping table kept as data in mappings.json.
package impact

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// The fixed set of Impacts a mapping may name.
var known = []string{
	"Read Data",
	"Modify Data",
	"Destroy Data",
	"Execute Code",
	"Escalate Privilege",
	"Exfiltrate",
	"Modify Identity",
}

//go:embed mappings.json
var mappingsJSON []byte

// Table is a parsed Impact mapping table.
type Table struct {
	Version  string    `json:"version"`
	Mappings []Mapping `json:"mappings"`
}

// Mapping attaches Impacts to one IAM action, written exactly as it appears
// in a policy.
type Mapping struct {
	Action  string   `json:"action"`
	Impacts []string `json:"impacts"`
	// Rationale says why the action has these Impacts. Every mapping needs
	// one, so a reviewer can check the mapping rather than trust it.
	Rationale string `json:"rationale"`
}

// Default returns the mapping table shipped with AgentGuard.
func Default() (*Table, error) {
	var t Table
	if err := json.Unmarshal(mappingsJSON, &t); err != nil {
		return nil, fmt.Errorf("impact mappings: %w", err)
	}
	for _, m := range t.Mappings {
		for _, i := range m.Impacts {
			if !slices.Contains(known, i) {
				return nil, fmt.Errorf("impact mappings: action %q names unknown Impact %q", m.Action, i)
			}
		}
	}
	return &t, nil
}

// Service returns the AWS service the mapping's action belongs to, such as
// "s3" for "s3:GetObject".
func (m Mapping) Service() string {
	service, _, _ := strings.Cut(m.Action, ":")
	return strings.ToLower(service)
}

// Source names the table in the evidence of an Impact, with its version.
func (t *Table) Source() string { return "agentguard:impact-mappings/v" + t.Version }

// Location is the JSONPath in the table of the mapping at index i.
func (t *Table) Location(i int) string { return fmt.Sprintf("$.mappings[%d]", i) }

// NoMappingLocation is the JSONPath in the table that evidence for an Impact
// of "unknown" points at: the whole list of mappings, none of which names the
// permission.
const NoMappingLocation = "$.mappings"

// Unknown is the Impact of a Native Permission that no mapping names.
const Unknown = "unknown"
