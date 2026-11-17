// Package linux is the Linux Collector. Collect reads a Linux host, through
// the narrow host.Host interface and as the user the Collector runs as, and
// returns a Snapshot of it.
//
// The Collector is read-only and works without root. Whatever it is denied,
// such as another user's home directory, it records as a Blind Spot so that
// analysis does not treat it as absent. It never records a secret value:
// credential files are recorded by location, owner, permissions, and
// fingerprint only.
package linux

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/imRYiUK/agentguard/collector/host"
	snapshotv1 "github.com/imRYiUK/agentguard/proto/gen/go/agentguard/snapshot/v1"
)

// SchemaVersion is the Snapshot schema version the Collector writes.
const SchemaVersion = "1"

// Limits on what the Collector reads, so a hostile or broken host cannot make
// it use unbounded memory or write a Snapshot AgentGuard refuses to read.
const (
	// maxSmallFileBytes is the size limit of the system files the Collector
	// reads: /etc/passwd, /etc/group, the machine ID, and SSH public keys.
	maxSmallFileBytes = 1 << 20
	// maxCredentialFileBytes is the size limit of a credential file.
	maxCredentialFileBytes = 1 << 20
	// maxAccounts is the number of accounts whose home directories are
	// searched for credential files.
	maxAccounts = 1024
	// maxProfiles is the number of profiles recorded from one credential
	// file.
	maxProfiles = 256
)

// minSecretLength is the length from which a value read from a credential
// file is checked against the Snapshot.
const minSecretLength = 8

// dockerSocketPath is where the Docker daemon listens by default.
const dockerSocketPath = "/var/run/docker.sock"

// Options are the facts about a collection that do not come from the host.
type Options struct {
	// Version is the Collector's version.
	Version string
	// Now is the collection time.
	Now time.Time
	// SnapshotID is the unique ID of the Snapshot.
	SnapshotID string
}

// Collect reads the host and returns its Snapshot. It fails only when it
// cannot establish which host it is looking at, because a Snapshot without an
// identity cannot be matched to an Environment. Everything else it cannot
// read becomes a Blind Spot.
//
// The agent user is the user the Collector runs as: run the Collector as the
// user the agent runs as.
func Collect(h host.Host, opts Options) (*snapshotv1.Snapshot, error) {
	switch {
	case opts.Version == "":
		return nil, errors.New("collect: the Collector version is required")
	case opts.SnapshotID == "":
		return nil, errors.New("collect: the Snapshot ID is required")
	case opts.Now.IsZero():
		return nil, errors.New("collect: the collection time is required")
	}
	c := &collector{h: h}

	env, err := c.environmentIdentity()
	if err != nil {
		return nil, err
	}
	accounts := c.readAccounts()
	user := c.agentUser(accounts)
	payload := &snapshotv1.LinuxPayload{
		AgentUser:       user,
		CredentialFiles: c.credentialFiles(accounts),
		DockerSocket:    c.dockerSocket(),
	}
	snap := &snapshotv1.Snapshot{
		SchemaVersion:    SchemaVersion,
		SnapshotId:       opts.SnapshotID,
		CollectorVersion: opts.Version,
		CollectedAt:      timestamppb.New(opts.Now.UTC()),
		CollectedBy:      user.GetName(),
		Environment:      &snapshotv1.EnvironmentIdentity{Identity: &snapshotv1.EnvironmentIdentity_Linux{Linux: env}},
		BlindSpots:       c.blindSpots,
		Payload:          &snapshotv1.Snapshot_Linux{Linux: payload},
	}
	if err := c.checkNoSecrets(snap); err != nil {
		return nil, err
	}
	return snap, nil
}

// MarshalJSON writes a Snapshot as Protobuf canonical JSON, indented and
// byte-stable.
func MarshalJSON(snap *snapshotv1.Snapshot) ([]byte, error) {
	// protojson deliberately varies its whitespace between builds, so the
	// output is re-indented to make it byte-stable.
	raw, err := protojson.Marshal(snap)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := json.Indent(&out, raw, "", "  "); err != nil {
		return nil, err
	}
	out.WriteByte('\n')
	return out.Bytes(), nil
}

// collector holds the state of one collection.
type collector struct {
	h          host.Host
	blindSpots []*snapshotv1.BlindSpot
	// secrets are the secret values read from credential files. They are
	// kept only to check, at the end, that none reached the Snapshot.
	secrets []string
}

func (c *collector) blind(attempted, reason string) {
	c.blindSpots = append(c.blindSpots, &snapshotv1.BlindSpot{Attempted: attempted, Reason: reason})
}

// reason describes why a read failed, in words that are the same on every
// host.
func reason(err error) string {
	var pe *fs.PathError
	switch {
	case errors.Is(err, fs.ErrPermission):
		return "permission denied"
	case errors.Is(err, host.ErrTooLarge):
		return "file is too large"
	case errors.As(err, &pe):
		return pe.Err.Error()
	}
	return err.Error()
}

// read reads a file. found is false when the file does not exist, which is
// not a Blind Spot: an absent file is a fact. A file that exists but cannot
// be read is a Blind Spot.
func (c *collector) read(path string, maxBytes int) (content []byte, found bool) {
	content, err := c.h.ReadFile(path, maxBytes)
	switch {
	case err == nil:
		return content, true
	case errors.Is(err, fs.ErrNotExist):
		return nil, false
	}
	c.blind("read "+path, reason(err))
	return nil, false
}

// checkNoSecrets is a last guard: it fails the collection if any secret value
// read from a credential file appears in the Snapshot. Nothing copies those
// values into it, so this is defence in depth against a future bug.
func (c *collector) checkNoSecrets(snap *snapshotv1.Snapshot) error {
	out, err := protojson.Marshal(snap)
	if err != nil {
		return err
	}
	for _, s := range c.secrets {
		// A value this short is not a secret worth the risk of rejecting a
		// Snapshot for matching a profile name by chance.
		if len(s) < minSecretLength {
			continue
		}
		quoted, _ := json.Marshal(s)
		if strings.Contains(string(out), s) || bytes.Contains(out, quoted[1:len(quoted)-1]) {
			return errors.New("collect: internal error: the Snapshot would contain a secret value, so it was not written")
		}
	}
	return nil
}

// modeString writes a file's permission bits in octal, with the setuid,
// setgid, and sticky bits as the fourth digit, for example "0640".
func modeString(m fs.FileMode) string {
	bits := uint32(m.Perm())
	if m&fs.ModeSetuid != 0 {
		bits |= 0o4000
	}
	if m&fs.ModeSetgid != 0 {
		bits |= 0o2000
	}
	if m&fs.ModeSticky != 0 {
		bits |= 0o1000
	}
	return fmt.Sprintf("%04o", bits)
}
