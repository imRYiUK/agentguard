package linux_test

import (
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/imRYiUK/agentguard/collector/host"
	"github.com/imRYiUK/agentguard/collector/hosttest"
	"github.com/imRYiUK/agentguard/collector/linux"
)

// The planted-secrets property: for any generated Environment, whatever
// secrets are planted in it, the Snapshot the Collector writes contains none
// of them. Each iteration builds a random host, plants secrets where a real
// host keeps them and where a hostile one might put them, collects it, and
// searches the Snapshot's JSON for every planted value.

const iterations = 500

var secretAlphabets = []string{
	"abcdefghijklmnopqrstuvwxyz",
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/+=",
	"abcdef0123456789",
	"pässwörd-секрет-秘密-🔑",
	`ab"\/ :;#[]=`,
}

// plant returns a random secret of at least 16 characters, so that it could
// not turn up in a Snapshot by chance.
func plant(r *rand.Rand) string {
	alphabet := []rune(secretAlphabets[r.IntN(len(secretAlphabets))])
	n := 16 + r.IntN(40)
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteRune(alphabet[r.IntN(len(alphabet))])
	}
	// A value with a newline or a leading blank would not survive being a
	// line of a file, so the planted value is what the parser would see.
	return strings.TrimSpace(strings.ReplaceAll(b.String(), "\n", "x")) + "Zq"
}

func pick[T any](r *rand.Rand, xs ...T) T { return xs[r.IntN(len(xs))] }

// randomEnvironment builds a fake host with credential files holding planted
// secrets in every position, and returns it with the planted values.
func randomEnvironment(r *rand.Rand) (*hosttest.Host, []string) {
	var planted []string
	next := func() string {
		s := plant(r)
		planted = append(planted, s)
		return s
	}
	entries := map[string]hosttest.Entry{
		"/etc/machine-id": {Lines: []string{goodMachineID}},
		"/var/run":        {Type: "dir", Mode: pick(r, "0755", "0700")},
	}
	var passwd, group []string
	group = append(group, "root:x:0:")
	nUsers := 1 + r.IntN(5)
	for i := 0; i < nUsers; i++ {
		uid := 1000 + i
		name := fmt.Sprintf("user%d", i)
		home := "/home/" + name
		// The GECOS field is free text that may hold anything.
		passwd = append(passwd, fmt.Sprintf("%s:x:%d:%d:%s:%s:%s", name, uid, uid, next(), home,
			pick(r, "/bin/bash", "/usr/sbin/nologin")))
		group = append(group, fmt.Sprintf("%s:x:%d:", name, uid))
		entries[home] = hosttest.Entry{Type: "dir", Mode: pick(r, "0755", "0750", "0700"), UID: uint32(uid), GID: uint32(uid)}
		entries[home+"/.aws"] = hosttest.Entry{Type: "dir", Mode: pick(r, "0755", "0700"), UID: uint32(uid), GID: uint32(uid)}
		entries[home+"/.aws/credentials"] = hosttest.Entry{
			Content: randomCredentialsFile(r, next),
			Mode:    pick(r, "0600", "0640", "0644", "0000", "0400"),
			UID:     uint32(uid),
			GID:     uint32(uid),
		}
		// Files that are not credential files, with secrets, which the
		// Collector has no reason to open.
		entries[home+"/.aws/config"] = hosttest.Entry{Content: "[default]\naws_secret_access_key = " + next() + "\n", Mode: "0644", UID: uint32(uid)}
		entries[home+"/.bash_history"] = hosttest.Entry{Content: "export TOKEN=" + next() + "\n", Mode: "0644", UID: uint32(uid)}
	}
	passwd = append(passwd, "root:x:0:0:root:/root:/bin/bash")
	entries["/root"] = hosttest.Entry{Type: "dir", Mode: pick(r, "0700", "0755")}
	entries["/root/.aws"] = hosttest.Entry{Type: "dir"}
	entries["/root/.aws/credentials"] = hosttest.Entry{Content: randomCredentialsFile(r, next), Mode: "0600"}
	entries["/etc/passwd"] = hosttest.Entry{Lines: passwd}
	entries["/etc/group"] = hosttest.Entry{Lines: group}
	entries["/var/run/docker.sock"] = hosttest.Entry{Type: "socket", Mode: "0660", GID: 998}

	uid := uint32(1000 + r.IntN(nUsers))
	return &hosttest.Host{Proc: host.Process{UID: uid, GID: uid}, Entries: entries}, planted
}

// randomCredentialsFile writes an AWS credentials file with planted secrets
// in the secret key, the session token, a made-up key, a comment, an access
// key ID, a section header that cannot be a profile name, and a line that is
// not a key at all.
func randomCredentialsFile(r *rand.Rand, next func() string) string {
	var b strings.Builder
	for i := 0; i < 1+r.IntN(4); i++ {
		switch r.IntN(4) {
		case 0:
			// A profile name is recorded by design, as `aws configure
			// list-profiles` prints it, so a secret a user wrote there is
			// not planted. A name that cannot be a profile name is dropped.
			fmt.Fprintf(&b, "[%s]\n", pick(r, fmt.Sprintf("profile%d", i), next()+" with spaces"))
		case 1:
			fmt.Fprintf(&b, "[ %s ]\n", fmt.Sprintf("p%d", i))
		default:
			fmt.Fprintf(&b, "[default%d]\n", i)
		}
		fmt.Fprintf(&b, "aws_access_key_id = %s\n", pick(r, "AKIAIOSFODNN7EXAMPLE", next()))
		fmt.Fprintf(&b, "aws_secret_access_key%s%s\n", pick(r, " = ", "=", "\t=\t"), next())
		if r.IntN(2) == 0 {
			fmt.Fprintf(&b, "aws_session_token = %s\n", next())
		}
		if r.IntN(2) == 0 {
			fmt.Fprintf(&b, "my_password = %s\n", next())
		}
		if r.IntN(2) == 0 {
			fmt.Fprintf(&b, "# old key: %s\n", next())
		}
		if r.IntN(3) == 0 {
			fmt.Fprintf(&b, "%s\n", next())
		}
	}
	return b.String()
}

func TestCollectNeverWritesAPlantedSecret(t *testing.T) {
	for seed := uint64(0); seed < iterations; seed++ {
		r := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
		h, planted := randomEnvironment(r)
		snap, err := linux.Collect(h, testOptions)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		out, err := linux.MarshalJSON(snap)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		for i, secret := range planted {
			if strings.Contains(string(out), secret) {
				t.Fatalf("seed %d: the Snapshot contains planted secret #%d (%d characters)", seed, i, len(secret))
			}
		}
	}
}
