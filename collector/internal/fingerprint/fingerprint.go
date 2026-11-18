// Package fingerprint is how the Collectors turn a secret-adjacent value,
// such as an access key ID, into something safe to record. Every Collector
// uses it, because a fingerprint links two Snapshots only if both were made
// the same way: a Linux Snapshot's credential profile and an AWS Snapshot's
// Identity are matched by it.
package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
)

// Of returns the fingerprint of b: "sha256:" and its SHA-256 in hex.
func Of(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}
