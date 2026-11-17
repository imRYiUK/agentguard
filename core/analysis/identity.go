package analysis

import (
	"fmt"

	snapshotv1 "github.com/imRYiUK/agentguard/proto/gen/go/agentguard/snapshot/v1"

	"github.com/imRYiUK/agentguard/core/internal/manifest"
)

// checkEnvironmentIdentity rejects a Snapshot that does not describe the
// Environment the manifest names for it, so the wrong host or account is
// never analyzed by mistake.
func checkEnvironmentIdentity(source string, env manifest.Environment, snap *snapshotv1.Snapshot) error {
	mismatch := func(format string, args ...any) error {
		return fmt.Errorf("%s: Environment identity mismatch: Environment %q (environments[%d]) %s",
			source, env.Name, env.Index, fmt.Sprintf(format, args...))
	}

	switch env.Type {
	case manifest.TypeLinux:
		if _, ok := snap.GetPayload().(*snapshotv1.Snapshot_Linux); !ok {
			return mismatch("is a linux Environment, but the Snapshot is not a linux Snapshot")
		}
		id := snap.GetEnvironment().GetLinux()
		if id == nil {
			return mismatch("expects a linux identity, but the Snapshot records none")
		}
		if env.MachineID != "" && env.MachineID != id.GetMachineId() {
			return mismatch("expects machineId %q, but the Snapshot records machineId %q", env.MachineID, id.GetMachineId())
		}
		if env.SSHHostKeyFingerprint != "" && env.SSHHostKeyFingerprint != id.GetSshHostKeyFingerprint() {
			return mismatch("expects sshHostKeyFingerprint %q, but the Snapshot records sshHostKeyFingerprint %q",
				env.SSHHostKeyFingerprint, id.GetSshHostKeyFingerprint())
		}
	case manifest.TypeAWS:
		if _, ok := snap.GetPayload().(*snapshotv1.Snapshot_Aws); !ok {
			return mismatch("is an aws Environment, but the Snapshot is not an aws Snapshot")
		}
		id := snap.GetEnvironment().GetAws()
		if id == nil {
			return mismatch("expects an aws identity, but the Snapshot records none")
		}
		if env.AccountID != id.GetAccountId() {
			return mismatch("expects accountId %q, but the Snapshot records accountId %q", env.AccountID, id.GetAccountId())
		}
	}
	return nil
}
