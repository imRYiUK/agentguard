// Package hosttest is a fake machine for testing the Collector. It holds an
// in-memory tree of files with owners and permission bits, and it enforces
// them the way the kernel does for an unprivileged process: a path is
// reachable only if every directory on the way is searchable, and a file is
// readable only if its permission bits grant the fake process read access.
// A fake Environment can therefore describe a host where the Collector is
// denied half of what it looks for, with no root and no real files.
package hosttest

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/imRYiUK/agentguard/collector/host"
)

// Entry is one path in the fake tree.
type Entry struct {
	// Type is "file" (the default), "dir", or "socket".
	Type string `json:"type,omitempty"`
	// Lines is the content of a file, one string per line, each ended by a
	// newline.
	Lines []string `json:"lines,omitempty"`
	// Content is the exact content of a file. It is used when Lines is empty.
	Content string `json:"content,omitempty"`
	// Mode is the permission bits in octal, for example "0640".
	Mode string `json:"mode,omitempty"`
	UID  uint32 `json:"uid,omitempty"`
	GID  uint32 `json:"gid,omitempty"`
}

// Host is a fake machine. It implements host.Host.
type Host struct {
	Proc host.Process
	// Entries are the paths of the tree. A directory that is not listed is
	// assumed to be owned by root with mode 0755.
	Entries map[string]Entry
}

// Environment is the JSON form of a fake Environment, used by golden
// fixtures.
type Environment struct {
	Process struct {
		UID    uint32   `json:"uid"`
		GID    uint32   `json:"gid"`
		Groups []uint32 `json:"groups,omitempty"`
	} `json:"process"`
	Entries map[string]Entry `json:"entries"`
}

// Load reads a fake Environment from a JSON file.
func Load(file string) (*Host, error) {
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var env Environment
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	return &Host{
		Proc:    host.Process{UID: env.Process.UID, GID: env.Process.GID, Groups: env.Process.Groups},
		Entries: env.Entries,
	}, nil
}

// Process implements host.Host.
func (h *Host) Process() host.Process { return h.Proc }

func (e Entry) perm() fs.FileMode {
	if e.Mode == "" {
		if e.Type == "dir" {
			return 0o755
		}
		return 0o644
	}
	m, err := strconv.ParseUint(e.Mode, 8, 12)
	if err != nil {
		panic(fmt.Sprintf("hosttest: bad mode %q", e.Mode))
	}
	return fs.FileMode(m)
}

func (e Entry) info() host.FileInfo {
	mode := e.perm()
	switch e.Type {
	case "dir":
		mode |= fs.ModeDir
	case "socket":
		mode |= fs.ModeSocket
	}
	return host.FileInfo{Mode: mode, UID: e.UID, GID: e.GID}
}

// allows reports whether the fake process may use bit (4 read, 2 write, 1
// search or execute) of a file with the given owner and permissions.
func (h *Host) allows(info host.FileInfo, bit fs.FileMode) bool {
	p := h.Proc
	if p.UID == 0 {
		return true
	}
	perm := info.Mode.Perm()
	switch {
	case p.UID == info.UID:
		return perm>>6&bit != 0
	case p.GID == info.GID || slices.Contains(p.Groups, info.GID):
		return perm>>3&bit != 0
	default:
		return perm&bit != 0
	}
}

func denied(op, p string) error {
	return &fs.PathError{Op: op, Path: p, Err: fs.ErrPermission}
}

// Stat implements host.Host.
func (h *Host) Stat(p string) (host.FileInfo, error) {
	if !path.IsAbs(p) || path.Clean(p) != p {
		return host.FileInfo{}, &fs.PathError{Op: "stat", Path: p, Err: fs.ErrInvalid}
	}
	return h.stat(p)
}

func (h *Host) stat(p string) (host.FileInfo, error) {
	for parent := path.Dir(p); parent != "/" && parent != "."; parent = path.Dir(parent) {
		e, listed := h.Entries[parent]
		if !listed {
			continue
		}
		if e.Type != "dir" {
			return host.FileInfo{}, &fs.PathError{Op: "stat", Path: p, Err: fs.ErrNotExist}
		}
		if !h.allows(e.info(), 1) {
			return host.FileInfo{}, denied("stat", p)
		}
	}
	e, ok := h.Entries[p]
	if !ok {
		return host.FileInfo{}, &fs.PathError{Op: "stat", Path: p, Err: fs.ErrNotExist}
	}
	return e.info(), nil
}

// ReadFile implements host.Host.
func (h *Host) ReadFile(p string, maxBytes int) ([]byte, error) {
	info, err := h.Stat(p)
	if err != nil {
		return nil, err
	}
	if !info.Mode.IsRegular() {
		return nil, &fs.PathError{Op: "read", Path: p, Err: fs.ErrInvalid}
	}
	if !h.allows(info, 4) {
		return nil, denied("open", p)
	}
	e := h.Entries[p]
	content := e.Content
	if len(e.Lines) > 0 {
		content = strings.Join(e.Lines, "\n") + "\n"
	}
	if len(content) > maxBytes {
		return nil, fmt.Errorf("%s: %w (the limit is %d bytes)", p, host.ErrTooLarge, maxBytes)
	}
	return []byte(content), nil
}
