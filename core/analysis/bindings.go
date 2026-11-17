package analysis

import (
	"fmt"
	"slices"
	"strings"

	analysisv1 "github.com/imRYiUK/agentguard/proto/gen/go/agentguard/analysis/v1"

	"github.com/imRYiUK/agentguard/core/internal/manifest"
)

// bindingMismatches returns a Secondary Finding for each Declared Binding in
// the manifest that a Discovered Binding contradicts. A Linux Environment
// contradicts it when the agent user the Snapshot records has another name.
// An AWS Environment contradicts it when the agent can read credentials that
// resolve to AWS Identities there, and none of them is the declared one.
// Nothing discovered is not a contradiction: the evidence may simply be
// missing.
func bindingMismatches(m *manifest.Manifest, hosts []*linuxHost, identities []*awsIdentity) []*analysisv1.SecondaryFinding {
	var out []*analysisv1.SecondaryFinding
	for _, declared := range m.DeclaredBindings {
		at := slices.IndexFunc(m.Environments, func(e manifest.Environment) bool { return e.Name == declared.Environment })
		if at < 0 {
			continue // the manifest parser rejects this, so it cannot happen
		}
		env := m.Environments[at]
		var discovered []string
		var what string
		switch env.Type {
		case manifest.TypeLinux:
			what = "Linux user"
			for _, host := range hosts {
				if host.environment == env.Name {
					discovered = append(discovered, host.payload.GetAgentUser().GetName())
				}
			}
		case manifest.TypeAWS:
			what = "AWS Identity"
			for _, host := range hosts {
				for _, hop := range host.agentHops {
					if id := hop.Via.identity; id != nil && id.environment == env.Name &&
						!slices.Contains(discovered, id.identity.GetArn()) {
						discovered = append(discovered, id.identity.GetArn())
					}
				}
			}
		}
		if len(discovered) == 0 || slices.Contains(discovered, declared.Identity) {
			continue
		}
		var evidence string
		if env.Type == manifest.TypeLinux {
			evidence = "the Snapshot shows the agent runs as " + strings.Join(discovered, ", ")
		} else {
			evidence = "the credentials the agent can read there resolve to " + strings.Join(discovered, ", ")
		}
		out = append(out, &analysisv1.SecondaryFinding{
			Kind:            analysisv1.SecondaryFindingKind_SECONDARY_FINDING_KIND_BINDING_MISMATCH,
			AgentDeployment: m.Agent.Name,
			Label: fmt.Sprintf("declared binding contradicts discovered binding: the manifest declares %s %s in Environment %s, but %s",
				what, declared.Identity, env.Name, evidence),
			Evidence:   &analysisv1.Evidence{Source: ManifestFile, Location: fmt.Sprintf("$.declaredBindings[%d]", declared.Index)},
			Confidence: analysisv1.Confidence_CONFIDENCE_HIGH,
		})
	}
	return out
}
