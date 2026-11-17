package analysis

import (
	"fmt"
	"slices"

	analysisv1 "github.com/imRYiUK/agentguard/proto/gen/go/agentguard/analysis/v1"
	snapshotv1 "github.com/imRYiUK/agentguard/proto/gen/go/agentguard/snapshot/v1"

	"github.com/imRYiUK/agentguard/core/internal/hopsearch"
)

// dockerGroup is the name of the Linux group whose members can talk to the
// Docker daemon.
const dockerGroup = "docker"

// Search nodes of one host. AWS Identities are named by their position in the
// list of AWS Identities.
const (
	nodeAgentUser = "agent user"
	nodeRoot      = "root"
)

func awsNode(i int) string { return fmt.Sprintf("aws %d", i) }

// step is the evidence of one Identity Hop in a chain: the hop itself, and
// the Identity it arrives at.
type step struct {
	link *analysisv1.Link
	// toLink is the Identity link of the Identity the hop arrives at.
	toLink *analysisv1.Link
	// identity is the AWS Identity the hop arrives at. It is nil when the
	// hop arrives at root on the host.
	identity *awsIdentity
}

// findChains searches for the Identity Hop chains that lead away from the
// host's agent user, at most hopsearch.MaxDepth hops long. The hops are:
//
//   - a credential file the user can read, to the AWS Identity its profile
//     resolves to;
//   - membership of the docker group, to root on the host. Root can read
//     every credential file.
func (h *linuxHost) findChains(identities []*awsIdentity) error {
	user := h.payload.GetAgentUser()
	agentHops, err := credentialHops(h, user, identities)
	if err != nil {
		return err
	}
	rootHops, err := credentialHops(h, &snapshotv1.LinuxUser{Name: "root"}, identities)
	if err != nil {
		return err
	}
	h.agentHops = agentHops

	agent := slices.Clone(agentHops)
	if i := slices.IndexFunc(user.GetGroups(), func(g *snapshotv1.LinuxGroup) bool { return g.GetName() == dockerGroup }); i >= 0 && user.GetUid() != 0 {
		group := user.GetGroups()[i]
		location := fmt.Sprintf("$.linux.agentUser.groups[%d]", i)
		root := bindingLink(analysisv1.BindingOrigin_BINDING_ORIGIN_INFERRED,
			"root on host "+h.environment, h.source, location)
		root.Confidence = analysisv1.Confidence_CONFIDENCE_REDUCED
		root.ConfidenceReason = "root access through the docker group is inferred, not observed: " +
			"rootless Docker or user-namespace remapping would not give it"
		agent = append(agent, hopsearch.Hop[step]{To: nodeRoot, Via: step{
			link: link(analysisv1.LinkKind_LINK_KIND_IDENTITY_HOP,
				fmt.Sprintf("member of the docker group (gid %d), which can run containers as root on the host", group.GetGid()),
				h.source, location),
			toLink: root,
		}})
	}

	h.chains = hopsearch.Search(nodeAgentUser, hopsearch.MaxDepth, func(node string) []hopsearch.Hop[step] {
		switch node {
		case nodeAgentUser:
			return agent
		case nodeRoot:
			return rootHops
		}
		return nil
	})
	return nil
}

// credentialHops returns the Identity Hops from a Linux user to AWS
// Identities, through AWS credential files on the host that the user can
// read.
func credentialHops(host *linuxHost, user *snapshotv1.LinuxUser, identities []*awsIdentity) ([]hopsearch.Hop[step], error) {
	var hops []hopsearch.Hop[step]
	for i, file := range host.payload.GetCredentialFiles() {
		if file.GetKind() != snapshotv1.CredentialKind_CREDENTIAL_KIND_AWS_SHARED_CREDENTIALS {
			continue
		}
		readable, err := canRead(user, file)
		if err != nil {
			return nil, fmt.Errorf("%s: invalid Snapshot: $.linux.credentialFiles[%d].mode: %w", host.source, i, err)
		}
		if !readable {
			continue
		}
		for j, profile := range file.GetAwsProfiles() {
			for k, ident := range identities {
				if profile.GetAccessKeyIdFingerprint() == "" ||
					!slices.Contains(ident.identity.GetAccessKeyIdFingerprints(), profile.GetAccessKeyIdFingerprint()) {
					continue
				}
				hops = append(hops, hopsearch.Hop[step]{To: awsNode(k), Via: step{
					link: link(analysisv1.LinkKind_LINK_KIND_IDENTITY_HOP,
						fmt.Sprintf("can read AWS credential file %s (profile %s)", file.GetPath(), profile.GetName()),
						host.source, fmt.Sprintf("$.linux.credentialFiles[%d].awsProfiles[%d]", i, j)),
					toLink:   ident.link,
					identity: ident,
				}})
			}
		}
	}
	return hops, nil
}
