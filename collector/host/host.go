// Package host is the narrow interface through which the Collector reads the
// machine it runs on. The Collector touches nothing else, so a test can run
// it against a fake filesystem and fake process facts, and so what it can do
// to a host is easy to audit: it can stat and read files, and nothing more.
package host

import (
	"errors"
	"io/fs"
)

// ErrTooLarge is returned by ReadFile for a file larger than the limit.
var ErrTooLarge = errors.New("file is too large")

// FileInfo is what Stat reports about a path, with symbolic links followed.
type FileInfo struct {
	// Mode holds the file type and the permission bits, including setuid,
	// setgid, and sticky.
	Mode fs.FileMode
	// UID and GID are the owner and group of the file.
	UID, GID uint32
}

// Process holds the facts about the user the Collector runs as.
type Process struct {
	UID uint32
	// GID is the primary group. Groups are the supplementary groups.
	GID    uint32
	Groups []uint32
}

// Host is a machine the Collector reads. Every path is absolute. The errors
// are those of the os package: errors.Is(err, fs.ErrNotExist) reports an
// absent path, and errors.Is(err, fs.ErrPermission) a path the Collector's
// user may not read.
type Host interface {
	// Stat reports the type, permissions, and ownership of a path.
	Stat(path string) (FileInfo, error)
	// ReadFile returns the contents of a regular file, or ErrTooLarge when
	// the file is larger than maxBytes. It never reads more than maxBytes+1
	// bytes.
	ReadFile(path string, maxBytes int) ([]byte, error)
	// Process reports the user the Collector runs as.
	Process() Process
}
