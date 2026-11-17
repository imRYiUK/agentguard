package linux_test

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/imRYiUK/agentguard/collector/hosttest"
	"github.com/imRYiUK/agentguard/collector/linux"
)

// The golden tests. Each folder under testdata/environments holds a fake
// Environment (environment.json: the fake process, and the files with their
// owners and permissions) and the Snapshot the Collector must produce for it
// (expected.json), compared byte for byte.
//
// Regenerate expected files after an intended change with:
//
//	go test ./linux -update
//
// and review the diff before committing it.
var update = flag.Bool("update", false, "rewrite the expected Snapshot of every fake Environment")

const environmentsDir = "testdata/environments"

// testOptions are fixed so a Snapshot never depends on the real clock or on
// a random ID.
var testOptions = linux.Options{
	Version:    "0.0.0-test",
	Now:        time.Date(2026, 11, 17, 10, 0, 0, 0, time.UTC),
	SnapshotID: "snap-test-0001",
}

func TestCollectGolden(t *testing.T) {
	entries, err := os.ReadDir(environmentsDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("no fake Environments found")
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		t.Run(entry.Name(), func(t *testing.T) {
			dir := filepath.Join(environmentsDir, entry.Name())
			fake, err := hosttest.Load(filepath.Join(dir, "environment.json"))
			if err != nil {
				t.Fatal(err)
			}
			snap, err := linux.Collect(fake, testOptions)
			if err != nil {
				t.Fatal(err)
			}
			got, err := linux.MarshalJSON(snap)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "expected.json")
			if *update {
				if err := os.WriteFile(path, got, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("reading the expected Snapshot (run with -update to create it): %v", err)
			}
			if string(got) != string(want) {
				t.Errorf("Snapshot differs from %s (run with -update to accept)\n--- got ---\n%s\n--- want ---\n%s", path, got, want)
			}
		})
	}
}
