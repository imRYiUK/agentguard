package linux

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"regexp"
	"strings"

	snapshotv1 "github.com/imRYiUK/agentguard/proto/gen/go/agentguard/snapshot/v1"
)

var machineIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// machineIDPaths are where a Linux host keeps its machine ID, in order.
var machineIDPaths = []string{"/etc/machine-id", "/var/lib/dbus/machine-id"}

// hostKeyTypes are the SSH host key types the Collector looks for, in order.
// The first key found is the one recorded, so the Snapshot names the same key
// whenever the host has the same keys.
var hostKeyTypes = []string{"ed25519", "ecdsa", "rsa"}

// environmentIdentity reads the provider-native identity of the host: its
// machine ID and the fingerprint of its SSH host key. It fails if it finds
// neither, since the Snapshot could then not be matched to an Environment.
func (c *collector) environmentIdentity() (*snapshotv1.LinuxEnvironmentIdentity, error) {
	id := &snapshotv1.LinuxEnvironmentIdentity{}
	for _, path := range machineIDPaths {
		content, found := c.read(path, maxSmallFileBytes)
		if !found {
			continue
		}
		value := strings.TrimSpace(string(content))
		if !machineIDPattern.MatchString(value) {
			c.blind("read "+path, "not a valid machine ID")
			continue
		}
		id.MachineId = value
		break
	}
	for _, typ := range hostKeyTypes {
		path := "/etc/ssh/ssh_host_" + typ + "_key.pub"
		content, found := c.read(path, maxSmallFileBytes)
		if !found {
			continue
		}
		fp, err := hostKeyFingerprint(content)
		if err != nil {
			c.blind("read "+path, "not a valid SSH public key")
			continue
		}
		id.SshHostKeyFingerprint = fp
		break
	}
	if id.MachineId == "" && id.SshHostKeyFingerprint == "" {
		return nil, errors.New("collect: cannot identify this host: it has no readable /etc/machine-id and no readable SSH host key, " +
			"and a Snapshot must say which host it describes")
	}
	return id, nil
}

// hostKeyFingerprint returns the SHA256 fingerprint of an OpenSSH public key
// file, in the form ssh-keygen prints.
func hostKeyFingerprint(pub []byte) (string, error) {
	fields := strings.Fields(string(pub))
	if len(fields) < 2 {
		return "", errors.New("not a public key")
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil || len(blob) == 0 {
		return "", errors.New("not a public key")
	}
	sum := sha256.Sum256(blob)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]), nil
}
