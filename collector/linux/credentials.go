package linux

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/imRYiUK/agentguard/collector/internal/fingerprint"
	snapshotv1 "github.com/imRYiUK/agentguard/proto/gen/go/agentguard/snapshot/v1"
)

// awsCredentialsPath is where each account keeps its AWS shared credentials
// file, relative to its home directory.
const awsCredentialsPath = ".aws/credentials"

// profileName is the profile names the Collector records. Anything else is
// not recorded: a name is free text in a file the Collector does not trust,
// and a name that looks like a key would end up in the Snapshot.
var profileName = regexp.MustCompile(`^[A-Za-z0-9_.@+=,-]{1,32}$`)

// accessKeyID matches an AWS access key ID, which AgentGuard never writes
// into a Snapshot, not even as a profile name that happens to be one.
var accessKeyID = regexp.MustCompile(`^(?:AKIA|ASIA|AIDA|AROA|AGPA|ANPA|ANVA|APKA)[A-Z2-7]{16}$`)

// credentialFiles finds the AWS credential files in the home directories of
// the user the Collector runs as, root, and every account with a login
// shell. It records each file it can read by location, owner, permissions,
// and fingerprint, and each one it cannot as a Blind Spot.
func (c *collector) credentialFiles(a accounts) []*snapshotv1.CredentialFile {
	uid := c.h.Process().UID
	var homes []string
	for _, u := range a.users {
		if (u.uid == uid || u.uid == 0 || loginShell(u.shell)) && path.IsAbs(u.home) && path.Clean(u.home) != "/" {
			homes = append(homes, path.Clean(u.home))
		}
	}
	slices.Sort(homes)
	homes = slices.Compact(homes)
	if len(homes) > maxAccounts {
		c.blind("search the home directories of all accounts",
			fmt.Sprintf("the host has more than %d, and only the first %d (by path) were searched", maxAccounts, maxAccounts))
		homes = homes[:maxAccounts]
	}

	var files []*snapshotv1.CredentialFile
	for _, home := range homes {
		if f := c.awsCredentialFile(path.Join(home, awsCredentialsPath)); f != nil {
			files = append(files, f)
		}
	}
	return files
}

// awsCredentialFile records one candidate AWS credentials file. It returns
// nil when the file is absent or unreadable.
func (c *collector) awsCredentialFile(p string) *snapshotv1.CredentialFile {
	info, err := c.h.Stat(p)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			c.blind("read "+p, reason(err))
		}
		return nil
	}
	if !info.Mode.IsRegular() {
		c.blind("read "+p, "not a regular file")
		return nil
	}
	content, found := c.read(p, maxCredentialFileBytes)
	if !found {
		return nil
	}
	profiles, secrets, tooMany, unsupported := parseAWSCredentials(content)
	c.secrets = append(c.secrets, secrets...)
	if unsupported {
		c.blind("read "+p, "a profile with an unsupported name was not recorded")
	}
	if tooMany {
		c.blind("read "+p, fmt.Sprintf("only the first %d profiles were recorded", maxProfiles))
	}
	return &snapshotv1.CredentialFile{
		Path:        p,
		Kind:        snapshotv1.CredentialKind_CREDENTIAL_KIND_AWS_SHARED_CREDENTIALS,
		OwnerUid:    info.UID,
		GroupGid:    info.GID,
		Mode:        modeString(info.Mode),
		Fingerprint: fingerprint.Of(content),
		AwsProfiles: profiles,
	}
}

// sensitiveKey reports whether an INI key of a credentials file holds a
// secret, going by its name.
func sensitiveKey(key string) bool {
	for _, word := range []string{"secret", "token", "password", "key", "credential"} {
		if strings.Contains(key, word) {
			return true
		}
	}
	return false
}

// parseAWSCredentials reads an AWS shared credentials file. It returns the
// profiles, each with the fingerprint of its access key ID, and the secret
// values it saw. Those are returned only so the caller can check that none
// reaches the Snapshot: the profiles hold none of them.
func parseAWSCredentials(content []byte) (profiles []*snapshotv1.AwsCredentialProfile, secrets []string, tooMany, unsupported bool) {
	var current *snapshotv1.AwsCredentialProfile
	byName := map[string]*snapshotv1.AwsCredentialProfile{}
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "" || line[0] == '#' || line[0] == ';':
		case line[0] == '[' && strings.HasSuffix(line, "]"):
			name := strings.TrimSpace(line[1 : len(line)-1])
			current = nil
			if !profileName.MatchString(name) || accessKeyID.MatchString(name) {
				// Not recorded, and not echoed: see profileName. Its keys are
				// ignored, but its secrets are still tracked below.
				secrets = append(secrets, name)
				unsupported = true
				continue
			}
			if p, dup := byName[name]; dup {
				current = p
				continue
			}
			if len(profiles) >= maxProfiles {
				tooMany = true
				continue
			}
			current = &snapshotv1.AwsCredentialProfile{Name: name}
			byName[name] = current
			profiles = append(profiles, current)
		default:
			key, value, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			key, value = strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(value)
			if key == "aws_access_key_id" {
				secrets = append(secrets, value)
				if current != nil {
					current.AccessKeyIdFingerprint = fingerprint.Of([]byte(value))
				}
			} else if sensitiveKey(key) {
				secrets = append(secrets, value)
			}
		}
	}
	return profiles, secrets, tooMany, unsupported
}

// dockerSocket records the Docker daemon's socket, if the host has one.
func (c *collector) dockerSocket() *snapshotv1.DockerSocket {
	info, err := c.h.Stat(dockerSocketPath)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			c.blind("stat "+dockerSocketPath, reason(err))
		}
		return nil
	}
	if info.Mode&fs.ModeSocket == 0 {
		return nil
	}
	return &snapshotv1.DockerSocket{
		Path:     dockerSocketPath,
		OwnerUid: info.UID,
		GroupGid: info.GID,
		Mode:     modeString(info.Mode),
	}
}
