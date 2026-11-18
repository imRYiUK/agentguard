package aws_test

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/imRYiUK/agentguard/collector/aws"
	"github.com/imRYiUK/agentguard/collector/awstest"
)

// The golden tests. Each folder under testdata/accounts holds a fake AWS
// account (account.json: the credentials, the principals and policies, and
// the calls that fail) and the Snapshot the Collector must produce for it
// (expected.json), compared byte for byte.
//
// Regenerate expected files after an intended change with:
//
//	go test ./aws -update
//
// and review the diff before committing it.
var update = flag.Bool("update", false, "rewrite the expected Snapshot of every fake account")

const accountsDir = "testdata/accounts"

// testOptions are fixed so a Snapshot never depends on the real clock or on
// a random ID.
var testOptions = aws.Options{
	Version:    "0.0.0-test",
	Now:        time.Date(2026, 11, 17, 10, 0, 0, 0, time.UTC),
	SnapshotID: "snap-test-0001",
}

func TestCollectGolden(t *testing.T) {
	entries, err := os.ReadDir(accountsDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("no fake accounts found")
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		t.Run(entry.Name(), func(t *testing.T) {
			dir := filepath.Join(accountsDir, entry.Name())
			fake, err := awstest.Load(filepath.Join(dir, "account.json"))
			if err != nil {
				t.Fatal(err)
			}
			snap, err := aws.Collect(context.Background(), fake, testOptions)
			if err != nil {
				t.Fatal(err)
			}
			got, err := aws.MarshalJSON(snap)
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
