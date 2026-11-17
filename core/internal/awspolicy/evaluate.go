package awspolicy

import (
	"errors"
	"slices"

	"github.com/imRYiUK/agentguard/core/internal/limits"
)

// Budget limits the work of evaluating policies. A hostile policy can have
// patterns that make matching slow, so the work is counted, and an
// evaluation that runs out fails instead of running on.
type Budget struct {
	left      int
	exhausted bool
}

// NewBudget returns a Budget of the given number of matching steps.
func NewBudget(steps int) *Budget { return &Budget{left: steps} }

// spend uses one step. It reports false once the budget is gone.
func (b *Budget) spend() bool {
	if b.left <= 0 {
		b.exhausted = true
		return false
	}
	b.left--
	return true
}

// ErrBudgetExhausted is returned when an evaluation needs more work than its
// Budget allows.
var ErrBudgetExhausted = errors.New("IAM policy evaluation is too expensive for the work limit")

// Grant is one Native Permission an Identity has: an action on a resource,
// granted by an Allow statement and not removed by any Deny.
type Grant struct {
	// Statement is the Allow statement that grants it. It points into the
	// slice given to Evaluate.
	Statement *Statement
	// Action is the Action entry of the statement that covers the action
	// asked about. It is empty when the statement uses NotAction.
	Action string
	// Resource is the Resource entry the grant is on. It is empty when the
	// statement uses NotResource, which grants every resource but those the
	// statement lists.
	Resource string
	// Conditional is true when the grant depends on a Condition that is not
	// evaluated. Reason says which.
	Conditional bool
	Reason      string
}

// Evaluate returns the Grants of action under statements, which must be all
// the statements that apply to one Identity. action may itself contain
// wildcards, as an Impact mapping names an action; a Grant then covers all
// the actions it stands for. The result is in statement order. A nil budget
// is a fresh one of limits.MaxPolicyEvalSteps.
func Evaluate(statements []Statement, action string, budget *Budget) ([]Grant, error) {
	if budget == nil {
		budget = NewBudget(limits.MaxPolicyEvalSteps)
	}
	var grants []Grant
	for i := range statements {
		st := &statements[i]
		if st.Effect != Allow {
			continue
		}
		pattern, ok := allowedBy(st, action, budget)
		if !ok {
			continue
		}
		resources := st.Resources
		if len(st.NotResources) > 0 {
			resources = []string{""}
		}
		for _, resource := range resources {
			g := Grant{Statement: st, Action: pattern, Resource: resource}
			if st.Conditional {
				g.Conditional, g.Reason = true, reasonAllowCondition
			}
			if removeOrQualify(&g, statements, action, budget) {
				continue
			}
			grants = append(grants, g)
		}
	}
	if budget.exhausted {
		return nil, ErrBudgetExhausted
	}
	return grants, nil
}

// allowedBy reports whether an Allow statement covers the action, and the
// Action entry that does. A NotAction statement covers every action but the
// ones it lists. The action asked about may stand for many actions, so the
// statement covers it unless a NotAction entry covers all of them.
func allowedBy(st *Statement, action string, b *Budget) (string, bool) {
	if len(st.NotActions) > 0 {
		for _, pattern := range st.NotActions {
			if covers(pattern, action, true, b) {
				return "", false
			}
		}
		return "", true
	}
	for _, pattern := range st.Actions {
		if covers(pattern, action, true, b) {
			return pattern, true
		}
	}
	return "", false
}

// The reasons a Grant is Conditional.
const (
	reasonAllowCondition = "the Allow statement has a Condition, which AgentGuard does not evaluate"
	reasonDenyCondition  = "a Deny statement with a Condition may remove it, and AgentGuard does not evaluate Conditions"
)

// removeOrQualify applies the Deny statements to a grant. It reports true
// when an unconditional Deny removes the grant. A Deny with a Condition might
// apply or might not, so it only makes the grant Conditional.
func removeOrQualify(g *Grant, all []Statement, action string, b *Budget) bool {
	for i := range all {
		d := &all[i]
		if d.Effect != Deny || !deniesAction(d, action, b) || !deniesResource(d, g, b) {
			continue
		}
		if !d.Conditional {
			return true
		}
		if !g.Conditional {
			g.Conditional, g.Reason = true, reasonDenyCondition
		}
	}
	return false
}

// deniesAction reports whether a Deny statement covers every action that the
// action asked about stands for. A NotAction Deny covers every action but the
// ones it lists, which is only provable for an action without wildcards.
func deniesAction(d *Statement, action string, b *Budget) bool {
	if len(d.NotActions) > 0 {
		if hasWildcard(action) {
			return false
		}
		for _, pattern := range d.NotActions {
			if covers(pattern, action, true, b) {
				return false
			}
		}
		return true
	}
	for _, pattern := range d.Actions {
		if covers(pattern, action, true, b) {
			return true
		}
	}
	return false
}

// deniesResource reports whether a Deny statement covers every resource of
// the grant.
func deniesResource(d *Statement, g *Grant, b *Budget) bool {
	grantNot := g.Statement.NotResources
	switch {
	case len(grantNot) == 0 && len(d.NotResources) == 0:
		// A listed resource against listed resources.
		for _, pattern := range d.Resources {
			if covers(pattern, g.Resource, false, b) {
				return true
			}
		}
	case len(grantNot) == 0:
		// A listed resource against every resource but some. It is denied
		// when it provably avoids all of them.
		if hasWildcard(g.Resource) {
			return false
		}
		for _, pattern := range d.NotResources {
			if covers(pattern, g.Resource, false, b) {
				return false
			}
		}
		return true
	case len(d.NotResources) == 0:
		// Every resource but some, against listed resources. Only a Deny of
		// every resource covers it.
		for _, pattern := range d.Resources {
			if covers(pattern, "*", false, b) {
				return true
			}
		}
	default:
		// Every resource but some, against every resource but some others.
		// The Deny covers the grant when everything it leaves alone is
		// something the grant leaves out too.
		for _, left := range d.NotResources {
			if !slices.ContainsFunc(grantNot, func(excluded string) bool { return covers(excluded, left, false, b) }) {
				return false
			}
		}
		return true
	}
	return false
}
