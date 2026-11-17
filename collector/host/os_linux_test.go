package host_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/imRYiUK/agentguard/collector/host"
)

// These tests run the real OS host against a temporary tree. Every file in it
// belongs to the test's own user, so ownership can only be checked against
// that user.

func skipIfRoot(t *testing.T) {
	t.Helper()
	if os.Getuid() == 0 {
		t.Skip("root bypasses file permissions")
	}
}

func TestOSStatReportsModeAndOwner(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "f"), []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "f"), 0o640); err != nil {
		t.Fatal(err)
	}
	info, err := host.OS{Root: root}.Stat("/f")
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode.Perm() != 0o640 || !info.Mode.IsRegular() || info.UID != uint32(os.Getuid()) || info.GID != uint32(os.Getgid()) {
		t.Errorf("unexpected FileInfo %+v", info)
	}
}

func TestOSMapsErrors(t *testing.T) {
	skipIfRoot(t)
	root := t.TempDir()
	o := host.OS{Root: root}
	if _, err := o.ReadFile("/missing", 10); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a missing file: want ErrNotExist, got %v", err)
	}
	secret := filepath.Join(root, "secret")
	if err := os.WriteFile(secret, []byte("x"), 0o000); err != nil {
		t.Fatal(err)
	}
	if _, err := o.ReadFile("/secret", 10); !errors.Is(err, fs.ErrPermission) {
		t.Errorf("an unreadable file: want ErrPermission, got %v", err)
	}
	if err := os.Mkdir(filepath.Join(root, "locked"), 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(filepath.Join(root, "locked"), 0o700) })
	if _, err := o.Stat("/locked/f"); !errors.Is(err, fs.ErrPermission) {
		t.Errorf("a path under an unsearchable directory: want ErrPermission, got %v", err)
	}
}

func TestOSReadFileEnforcesTheLimit(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "f"), []byte("0123456789"), 0o600); err != nil {
		t.Fatal(err)
	}
	o := host.OS{Root: root}
	if got, err := o.ReadFile("/f", 10); err != nil || string(got) != "0123456789" {
		t.Errorf("a file of exactly the limit: got %q, %v", got, err)
	}
	if _, err := o.ReadFile("/f", 9); !errors.Is(err, host.ErrTooLarge) {
		t.Errorf("a file over the limit: want ErrTooLarge, got %v", err)
	}
}

func TestOSReadFileRefusesANamedPipeWithoutHanging(t *testing.T) {
	root := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(root, "pipe"), 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := host.OS{Root: root}.ReadFile("/pipe", 10)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Errorf("want a not-a-regular-file error, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reading a named pipe hung")
	}
}

func TestOSProcessIsTheCurrentUser(t *testing.T) {
	p := host.OS{}.Process()
	if p.UID != uint32(os.Getuid()) || p.GID != uint32(os.Getgid()) {
		t.Errorf("unexpected process %+v", p)
	}
}
