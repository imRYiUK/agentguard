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
}

// Match is one Impact attached to an action, with where it was attached.
type Match struct {
	Impact   string
	Source   string
	Location string
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

// Lookup returns the Impacts mapped to an IAM action. IAM action names are
// case-insensitive.
func (t *Table) Lookup(action string) []Match {
	var matches []Match
	for i, m := range t.Mappings {
		if !strings.EqualFold(m.Action, action) {
			continue
		}
		for _, imp := range m.Impacts {
			matches = append(matches, Match{
				Impact:   imp,
				Source:   "agentguard:impact-mappings/v" + t.Version,
				Location: fmt.Sprintf("$.mappings[%d]", i),
			})
		}
	}
	return matches
}
