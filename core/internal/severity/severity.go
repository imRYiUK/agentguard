// Package severity combines an Impact with a Resource Sensitivity into a
// severity, and finds the Resource Sensitivity that applies to a resource.
// Nothing here guesses: an Impact or a Resource Sensitivity that is unknown
// gives an unknown severity.
package severity

import (
	"errors"

	"github.com/imRYiUK/agentguard/core/internal/limits"
	"github.com/imRYiUK/agentguard/core/internal/manifest"
)

// Unknown is the severity, and the Resource Sensitivity, of anything the
// analysis has no label for.
const Unknown = "unknown"

// The severities, lowest first. Unknown is not part of the order.
const (
	Low      = "low"
	Medium   = "medium"
	High     = "high"
	Critical = "critical"
)

// impactWeight ranks the Impacts by how much damage they do, from 1 to 4. The
// weights are a judgement the documentation states, so a reviewer can
// challenge them.
var impactWeight = map[string]int{
	"Read Data":          1,
	"Modify Data":        2,
	"Destroy Data":       3,
	"Exfiltrate":         3,
	"Modify Identity":    3,
	"Execute Code":       4,
	"Escalate Privilege": 4,
}

// sensitivityWeight ranks the Resource Sensitivity levels from 1 to 4.
var sensitivityWeight = map[string]int{
	manifest.SensitivityLow:      1,
	manifest.SensitivityMedium:   2,
	manifest.SensitivityHigh:     3,
	manifest.SensitivityCritical: 4,
}

// Of returns the severity of an Impact on a resource of the given Resource
// Sensitivity: the product of their weights, banded. It is Unknown when
// either is unknown.
func Of(impact, sensitivity string) string {
	i, s := impactWeight[impact], sensitivityWeight[sensitivity]
	if i == 0 || s == 0 {
		return Unknown
	}
	switch p := i * s; {
	case p <= 2:
		return Low
	case p <= 4:
		return Medium
	case p <= 8:
		return High
	default:
		return Critical
	}
}

// ErrBudgetExhausted is returned when finding a Resource Sensitivity needs
// more work than the budget allows.
var ErrBudgetExhausted = errors.New("matching Resource Sensitivity labels is too expensive for the work limit")

// Resolver finds the Resource Sensitivity of resources from the labels of an
// Agent Manifest.
type Resolver struct {
	labels []manifest.ResourceSensitivity
	left   int
	cache  map[string]string
}

// NewResolver returns a Resolver for the labels, with a work budget of
// limits.MaxPolicyEvalSteps matching steps.
func NewResolver(labels []manifest.ResourceSensitivity) *Resolver {
	return &Resolver{labels: labels, left: limits.MaxPolicyEvalSteps, cache: map[string]string{}}
}

// SetBudget replaces the Resolver's work budget, in matching steps.
func (r *Resolver) SetBudget(steps int) { r.left = steps }

// Sensitivity returns the Resource Sensitivity of a resource pattern: the
// highest level among the labels whose pattern can match a resource the
// pattern matches, or Unknown when no label does. A permission on "*" can
// reach every labelled resource, so it takes the highest label; over-stating
// the reach is the safe direction.
func (r *Resolver) Sensitivity(resource string) (string, error) {
	if got, ok := r.cache[resource]; ok {
		return got, nil
	}
	best := Unknown
	for _, label := range r.labels {
		overlap, err := r.overlap(resource, label.Resource)
		if err != nil {
			return "", err
		}
		if overlap && (best == Unknown || sensitivityWeight[label.Sensitivity] > sensitivityWeight[best]) {
			best = label.Sensitivity
		}
	}
	r.cache[resource] = best
	return best, nil
}

// overlap reports whether some string matches both patterns. * matches any
// run of characters and ? matches one. It runs a table over the two patterns
// one row at a time, spending a step per cell.
func (r *Resolver) overlap(a, b string) (bool, error) {
	ar, br := []rune(a), []rune(b)
	// row[j] answers whether ar[i:] and br[j:] overlap, for the current i.
	row := make([]bool, len(br)+1)
	next := make([]bool, len(br)+1)
	// i == len(ar): the rest of b must be all stars.
	row[len(br)] = true
	for j := len(br) - 1; j >= 0; j-- {
		row[j] = br[j] == '*' && row[j+1]
	}
	for i := len(ar) - 1; i >= 0; i-- {
		next[len(br)] = ar[i] == '*' && row[len(br)]
		for j := len(br) - 1; j >= 0; j-- {
			if r.left--; r.left < 0 {
				return false, ErrBudgetExhausted
			}
			if ar[i] == '*' || br[j] == '*' {
				// A star matches nothing, so the other pattern moves on
				// past it, or it takes one more character of the other.
				next[j] = row[j] || next[j+1]
			} else {
				next[j] = (ar[i] == br[j] || ar[i] == '?' || br[j] == '?') && row[j+1]
			}
		}
		row, next = next, row
	}
	return row[0], nil
}
