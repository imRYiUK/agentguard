package linux_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/imRYiUK/agentguard/collector/host"
	"github.com/imRYiUK/agentguard/collector/hosttest"
	"github.com/imRYiUK/agentguard/collector/linux"
	snapshotv1 "github.com/imRYiUK/agentguard/proto/gen/go/agentguard/snapshot/v1"
)

const goodMachineID = "e8c913f01b6f9ef3d7f19c3cef1cc390"

// newHost returns a fake host with the identity files and the accounts of a
// small machine, running the Collector as the user "deploy" (uid 1001).
func newHost(extra map[string]hosttest.Entry) *hosttest.Host {
	entries := map[string]hosttest.Entry{
		"/etc/machine-id": {Lines: []string{goodMachineID}},
		"/etc/passwd": {Lines: []string{
			"root:x:0:0:root:/root:/bin/bash",
			"deploy:x:1001:1001::/home/deploy:/bin/bash",
		}},
		"/etc/group": {Lines: []string{"root:x:0:", "deploy:x:1001:"}},
	}
	for k, v := range extra {
		entries[k] = v
	}
	return &hosttest.Host{Proc: host.Process{UID: 1001, GID: 1001}, Entries: entries}
}

func collect(t *testing.T, h host.Host) *snapshotv1.Snapshot {
	t.Helper()
	snap, err := linux.Collect(h, testOptions)
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

func blindSpots(snap *snapshotv1.Snapshot) []string {
	var out []string
	for _, b := range snap.GetBlindSpots() {
		out = append(out, b.GetAttempted()+": "+b.GetReason())
	}
	return out
}

func wantBlindSpot(t *testing.T, snap *snapshotv1.Snapshot, want string) {
	t.Helper()
	for _, b := range blindSpots(snap) {
		if b == want {
			return
		}
	}
	t.Errorf("want the Blind Spot %q, got %q", want, blindSpots(snap))
}

func TestCollectRecordsProvenance(t *testing.T) {
	snap := collect(t, newHost(nil))
	if snap.GetSnapshotId() != "snap-test-0001" || snap.GetCollectorVersion() != "0.0.0-test" ||
		snap.GetCollectedBy() != "deploy" || snap.GetSchemaVersion() != "1" ||
		!snap.GetCollectedAt().AsTime().Equal(testOptions.Now) {
		t.Errorf("unexpected provenance: %v", snap)
	}
}

func TestCollectRequiresOptions(t *testing.T) {
	for name, opts := range map[string]linux.Options{
		"version": {Now: testOptions.Now, SnapshotID: "x"},
		"ID":      {Version: "v", Now: testOptions.Now},
		"time":    {Version: "v", SnapshotID: "x"},
	} {
		if _, err := linux.Collect(newHost(nil), opts); err == nil {
			t.Errorf("a missing %s was accepted", name)
		}
	}
}

func TestCollectRefusesAHostItCannotIdentify(t *testing.T) {
	h := newHost(nil)
	delete(h.Entries, "/etc/machine-id")
	if _, err := linux.Collect(h, testOptions); err == nil || !strings.Contains(err.Error(), "cannot identify this host") {
		t.Errorf("want a cannot-identify error, got %v", err)
	}
}

func TestCollectFallsBackToTheDBusMachineID(t *testing.T) {
	h := newHost(map[string]hosttest.Entry{
		"/etc/machine-id":          {Lines: []string{"not-a-machine-id"}},
		"/var/lib/dbus/machine-id": {Lines: []string{goodMachineID}},
	})
	snap := collect(t, h)
	if got := snap.GetEnvironment().GetLinux().GetMachineId(); got != goodMachineID {
		t.Errorf("machine ID = %q, want the dbus one", got)
	}
	wantBlindSpot(t, snap, "read /etc/machine-id: not a valid machine ID")
}

func TestCollectIdentifiesAHostByItsHostKeyAlone(t *testing.T) {
	h := newHost(map[string]hosttest.Entry{
		"/etc/ssh/ssh_host_rsa_key.pub": {Lines: []string{"ssh-rsa AAAAB3NzaC1yc2EAAAAD host"}},
	})
	delete(h.Entries, "/etc/machine-id")
	snap := collect(t, h)
	if snap.GetEnvironment().GetLinux().GetMachineId() != "" || snap.GetEnvironment().GetLinux().GetSshHostKeyFingerprint() == "" {
		t.Errorf("want a host key identity only, got %v", snap.GetEnvironment())
	}
}

func TestCollectRecordsAnUnreadableHostKeyAsABlindSpot(t *testing.T) {
	h := newHost(map[string]hosttest.Entry{
		"/etc/ssh/ssh_host_ed25519_key.pub": {Lines: []string{"ssh-ed25519 AAAA host"}, Mode: "0600", UID: 0, GID: 0},
	})
	wantBlindSpot(t, collect(t, h), "read /etc/ssh/ssh_host_ed25519_key.pub: permission denied")
}

func TestCollectNamesUsersAndGroupsTheHostDoesNotListByNumber(t *testing.T) {
	h := newHost(nil)
	h.Proc = host.Process{UID: 4242, GID: 4243, Groups: []uint32{1001, 4243}}
	snap := collect(t, h)
	user := snap.GetLinux().GetAgentUser()
	if user.GetName() != "uid-4242" || len(user.GetGroups()) != 2 ||
		user.GetGroups()[0].GetName() != "gid-4243" || user.GetGroups()[1].GetName() != "deploy" {
		t.Errorf("unexpected user %v", user)
	}
	wantBlindSpot(t, snap, "resolve the name of uid 4242: no entry in /etc/passwd")
	wantBlindSpot(t, snap, "resolve the name of gid 4243: no entry in /etc/group")
}

func TestCollectRecordsTheDockerGroupAndSocket(t *testing.T) {
	h := newHost(map[string]hosttest.Entry{
		"/etc/group":           {Lines: []string{"root:x:0:", "deploy:x:1001:", "docker:x:998:deploy"}},
		"/var/run/docker.sock": {Type: "socket", Mode: "0660", GID: 998},
	})
	h.Proc.Groups = []uint32{998}
	snap := collect(t, h)
	var groups []string
	for _, g := range snap.GetLinux().GetAgentUser().GetGroups() {
		groups = append(groups, fmt.Sprintf("%s:%d", g.GetName(), g.GetGid()))
	}
	if strings.Join(groups, ",") != "deploy:1001,docker:998" {
		t.Errorf("groups = %v", groups)
	}
	sock := snap.GetLinux().GetDockerSocket()
	if sock.GetPath() != "/var/run/docker.sock" || sock.GetGroupGid() != 998 || sock.GetMode() != "0660" {
		t.Errorf("unexpected socket %v", sock)
	}
}

func TestCollectIgnoresAnAbsentDockerSocketAndANonSocket(t *testing.T) {
	if sock := collect(t, newHost(nil)).GetLinux().GetDockerSocket(); sock != nil {
		t.Errorf("want no socket, got %v", sock)
	}
	h := newHost(map[string]hosttest.Entry{"/var/run/docker.sock": {Content: "not a socket"}})
	if sock := collect(t, h).GetLinux().GetDockerSocket(); sock != nil {
		t.Errorf("a regular file is not a socket, got %v", sock)
	}
}

func TestCollectLooksOnlyInHomesOfAccountsThatCanLogIn(t *testing.T) {
	creds := hosttest.Entry{Lines: []string{"[default]", "aws_access_key_id = AKIAEXAMPLE"}, Mode: "0644"}
	h := newHost(map[string]hosttest.Entry{
		"/etc/passwd": {Lines: []string{
			"root:x:0:0:root:/root:/bin/bash",
			"deploy:x:1001:1001::/home/deploy:/bin/bash",
			"daemon:x:1:1:daemon:/var/lib/daemon:/usr/sbin/nologin",
			"ops:x:1002:1002::/home/ops:/bin/zsh",
		}},
		"/var/lib/daemon/.aws/credentials": creds,
		"/home/ops/.aws/credentials":       creds,
		"/root/.aws/credentials":           creds,
	})
	var paths []string
	for _, f := range collect(t, h).GetLinux().GetCredentialFiles() {
		paths = append(paths, f.GetPath())
	}
	if got := strings.Join(paths, ","); got != "/home/ops/.aws/credentials,/root/.aws/credentials" {
		t.Errorf("credential files = %s", got)
	}
}

func TestCollectRecordsProfilesWithoutKeysAndSkipsUnsafeProfileNames(t *testing.T) {
	h := newHost(map[string]hosttest.Entry{
		"/home/deploy/.aws/credentials": {Mode: "0600", UID: 1001, GID: 1001, Lines: []string{
			"[empty]",
			"[AKIAIOSFODNN7EXAMPLE]",
			"aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
			"[ok]",
			"aws_access_key_id = AKIAJ3EXAMPLEKEYEXAM",
		}},
	})
	snap := collect(t, h)
	wantBlindSpot(t, snap, "read /home/deploy/.aws/credentials: a profile with an unsupported name was not recorded")
	files := snap.GetLinux().GetCredentialFiles()
	if len(files) != 1 || len(files[0].GetAwsProfiles()) != 2 {
		t.Fatalf("want one file with two profiles, got %v", files)
	}
	empty, ok := files[0].GetAwsProfiles()[0], files[0].GetAwsProfiles()[1]
	if empty.GetName() != "empty" || empty.GetAccessKeyIdFingerprint() != "" ||
		ok.GetName() != "ok" || ok.GetAccessKeyIdFingerprint() == "" {
		t.Errorf("unexpected profiles %v", files[0].GetAwsProfiles())
	}
}

func TestCollectRecordsALargeCredentialFileAsABlindSpot(t *testing.T) {
	h := newHost(map[string]hosttest.Entry{
		"/home/deploy/.aws/credentials": {Mode: "0600", UID: 1001, GID: 1001, Content: strings.Repeat("# padding\n", 200_000)},
	})
	snap := collect(t, h)
	if len(snap.GetLinux().GetCredentialFiles()) != 0 {
		t.Errorf("an oversized file was recorded")
	}
	wantBlindSpot(t, snap, "read /home/deploy/.aws/credentials: file is too large")
}

func TestCollectBoundsTheProfilesOfOneFile(t *testing.T) {
	var lines []string
	for i := 0; i < 300; i++ {
		lines = append(lines, fmt.Sprintf("[p%d]", i), "aws_access_key_id = AKIAJ3EXAMPLEKEYEXAM")
	}
	h := newHost(map[string]hosttest.Entry{
		"/home/deploy/.aws/credentials": {Mode: "0600", UID: 1001, GID: 1001, Lines: lines},
	})
	snap := collect(t, h)
	if n := len(snap.GetLinux().GetCredentialFiles()[0].GetAwsProfiles()); n != 256 {
		t.Errorf("recorded %d profiles, want 256", n)
	}
	wantBlindSpot(t, snap, "read /home/deploy/.aws/credentials: only the first 256 profiles were recorded")
}
