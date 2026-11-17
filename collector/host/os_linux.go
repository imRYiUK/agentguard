package host

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// OS is the real machine. Root, when set, is a directory the absolute paths
// are resolved under, so a test can point the Collector at a temporary tree.
// An empty Root is the real filesystem root. Symbolic links inside a Root
// still resolve against the real filesystem, so Root is for tests only.
type OS struct {
	Root string
}

func (o OS) resolve(path string) string {
	if o.Root == "" {
		return path
	}
	return filepath.Join(o.Root, path)
}

// Stat implements Host.
func (o OS) Stat(path string) (FileInfo, error) {
	info, err := os.Stat(o.resolve(path))
	if err != nil {
		return FileInfo{}, err
	}
	return fileInfo(info)
}

func fileInfo(info fs.FileInfo) (FileInfo, error) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return FileInfo{}, errors.New("the file system does not report ownership")
	}
	return FileInfo{Mode: info.Mode(), UID: st.Uid, GID: st.Gid}, nil
}

// ReadFile implements Host. It opens without blocking and refuses anything
// but a regular file, so a named pipe or a device at a credential path cannot
// hang the Collector.
func (o OS) ReadFile(path string, maxBytes int) ([]byte, error) {
	f, err := os.OpenFile(o.resolve(path), os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, &fs.PathError{Op: "read", Path: path, Err: errors.New("not a regular file")}
	}
	content, err := io.ReadAll(io.LimitReader(f, int64(maxBytes)+1))
	if err != nil {
		return nil, err
	}
	if len(content) > maxBytes {
		return nil, fmt.Errorf("%s: %w (the limit is %d bytes)", path, ErrTooLarge, maxBytes)
	}
	return content, nil
}

// Process implements Host.
func (OS) Process() Process {
	p := Process{UID: uint32(os.Getuid()), GID: uint32(os.Getgid())}
	groups, err := os.Getgroups()
	if err == nil {
		for _, g := range groups {
			p.Groups = append(p.Groups, uint32(g))
		}
	}
	return p
}
