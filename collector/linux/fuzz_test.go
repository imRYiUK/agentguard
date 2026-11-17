package linux_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/imRYiUK/agentguard/collector/hosttest"
	"github.com/imRYiUK/agentguard/collector/linux"
)

// FuzzCollectCredentialsFile feeds the Collector arbitrary credential file
// content. It must never panic, and must write valid JSON; the only error it
// may return is the guard that stops a Snapshot holding a secret value.
func FuzzCollectCredentialsFile(f *testing.F) {
	f.Add("[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n")
	f.Add("[a]\n[a]\n[b")
	f.Add("= = =\n[\n]\n[]\n;\n#")
	f.Add("[x]\naws_access_key_id\n\x00\xff")
	f.Fuzz(func(t *testing.T, content string) {
		h := newHost(map[string]hosttest.Entry{
			"/home/deploy/.aws/credentials": {Content: content, Mode: "0600", UID: 1001, GID: 1001},
		})
		snap, err := linux.Collect(h, testOptions)
		if err != nil {
			if !strings.Contains(err.Error(), "would contain a secret value") {
				t.Fatalf("unexpected error: %v", err)
			}
			return
		}
		out, err := linux.MarshalJSON(snap)
		if err != nil {
			t.Fatal(err)
		}
		if !json.Valid(out) {
			t.Fatalf("invalid JSON:\n%s", out)
		}
	})
}
