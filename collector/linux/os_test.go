package linux_test

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/imRYiUK/agentguard/collector/host"
	"github.com/imRYiUK/agentguard/collector/linux"
)

// TestCollectRealHostAsAnOrdinaryUser runs the Collector through the real OS
// host over a temporary tree, with a directory it may not enter, and checks
// that it finishes without root and records that directory as a Blind Spot.
func TestCollectRealHostAsAnOrdinaryUser(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root bypasses file permissions")
	}
	root := t.TempDir()
	write := func(name, content string, perm os.FileMode) {
		t.Helper()
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), perm); err != nil {
			t.Fatal(err)
		}
	}
	write("etc/machine-id", goodMachineID+"\n", 0o644)
	write("etc/passwd", "me:x:"+strconv.Itoa(os.Getuid())+":"+strconv.Itoa(os.Getgid())+"::/home/me:/bin/bash\nother:x:4000:4000::/home/other:/bin/bash\n", 0o644)
	write("home/me/.aws/credentials", "[default]\naws_access_key_id = AKIAJ3EXAMPLEKEYEXAM\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n", 0o600)
	if err := os.MkdirAll(filepath.Join(root, "home/other"), 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(filepath.Join(root, "home/other"), 0o700) })

	snap, err := linux.Collect(host.OS{Root: root}, testOptions)
	if err != nil {
		t.Fatal(err)
	}
	if snap.GetCollectedBy() != "me" || len(snap.GetLinux().GetCredentialFiles()) != 1 {
		t.Errorf("unexpected Snapshot %v", snap)
	}
	if f := snap.GetLinux().GetCredentialFiles()[0]; f.GetMode() != "0600" || f.GetOwnerUid() != uint32(os.Getuid()) {
		t.Errorf("unexpected credential file %v", f)
	}
	wantBlindSpot(t, snap, "read /home/other/.aws/credentials: permission denied")
}
