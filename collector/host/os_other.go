//go:build !linux

package host

import "errors"

// OS is not available off Linux: the Collector reads Linux hosts only.
type OS struct{ Root string }

var errNotLinux = errors.New("the Linux Collector runs on Linux only")

func (OS) Stat(string) (FileInfo, error)        { return FileInfo{}, errNotLinux }
func (OS) ReadFile(string, int) ([]byte, error) { return nil, errNotLinux }
func (OS) Process() Process                     { return Process{} }
