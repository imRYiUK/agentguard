// Package snapshotjson writes a Snapshot in the one form every Collector
// uses: Protobuf canonical JSON, indented and byte-stable.
package snapshotjson

import (
	"bytes"
	"encoding/json"

	"google.golang.org/protobuf/encoding/protojson"

	snapshotv1 "github.com/imRYiUK/agentguard/proto/gen/go/agentguard/snapshot/v1"
)

// Marshal writes a Snapshot as Protobuf canonical JSON.
func Marshal(snap *snapshotv1.Snapshot) ([]byte, error) {
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
