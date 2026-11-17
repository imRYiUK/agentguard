package analysis

import (
	"fmt"
	"strings"

	analysisv1 "github.com/imRYiUK/agentguard/proto/gen/go/agentguard/analysis/v1"

	"github.com/imRYiUK/agentguard/core/internal/agentconfig"
	"github.com/imRYiUK/agentguard/core/internal/awspolicy"
)

// secondaryFindings returns the single-layer issues in the Analysis Input:
// shell Tools, then filesystem Tools given a broad directory, then wildcard
// policies. They do not depend on any Identity Hop, so they are reported
// whether or not a Reach Path exists.
func secondaryFindings(deployment string, shell []agentconfig.ShellTool, filesystem []agentconfig.FilesystemTool, identities []*awsIdentity) []*analysisv1.SecondaryFinding {
	var out []*analysisv1.SecondaryFinding
	add := func(kind analysisv1.SecondaryFindingKind, label, source, location string) *analysisv1.SecondaryFinding {
		f := &analysisv1.SecondaryFinding{
			Kind:            kind,
			AgentDeployment: deployment,
			Label:           label,
			Evidence:        &analysisv1.Evidence{Source: source, Location: location},
			Confidence:      analysisv1.Confidence_CONFIDENCE_HIGH,
		}
		out = append(out, f)
		return f
	}

	for _, tool := range shell {
		add(analysisv1.SecondaryFindingKind_SECONDARY_FINDING_KIND_UNRESTRICTED_COMMAND_EXECUTION,
			fmt.Sprintf("unrestricted command execution: shell Tool (MCP server %s)", tool.Server),
			tool.Source, tool.Location)
	}
	for _, tool := range filesystem {
		add(analysisv1.SecondaryFindingKind_SECONDARY_FINDING_KIND_BROAD_FILESYSTEM_ACCESS,
			fmt.Sprintf("broad filesystem access: MCP server %s is given %s", tool.Server, tool.Root),
			tool.Source, tool.Location)
	}
	for _, ident := range identities {
		for i := range ident.statements {
			st := &ident.statements[i]
			if !st.Wildcard() {
				continue
			}
			f := add(analysisv1.SecondaryFindingKind_SECONDARY_FINDING_KIND_WILDCARD_POLICY,
				fmt.Sprintf("wildcard policy: Allow %s on %s (%s)", strings.Join(st.Actions, ", "), statementResources(st), awsIdentityLabel(ident.identity.GetArn())),
				ident.source, ident.statementLocation(st))
			if st.Conditional {
				f.Confidence = analysisv1.Confidence_CONFIDENCE_REDUCED
				f.ConfidenceReason = awspolicy.ReasonAllowCondition
			}
		}
	}
	return out
}

// statementResources describes the resources a statement allows, as the
// policy states them.
func statementResources(st *awspolicy.Statement) string {
	if len(st.NotResources) > 0 {
		return "all resources except " + strings.Join(st.NotResources, ", ")
	}
	return strings.Join(st.Resources, ", ")
}
