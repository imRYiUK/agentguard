package linux

import (
	"fmt"
	"path"
	"slices"
	"strconv"
	"strings"

	snapshotv1 "github.com/imRYiUK/agentguard/proto/gen/go/agentguard/snapshot/v1"
)

// account is one line of /etc/passwd.
type account struct {
	name     string
	uid, gid uint32
	home     string
	shell    string
}

// accounts are the users and groups of the host, from /etc/passwd and
// /etc/group.
type accounts struct {
	users  []account
	groups map[uint32]string
}

func (c *collector) readAccounts() accounts {
	var a accounts
	if content, found := c.read("/etc/passwd", maxSmallFileBytes); found {
		for _, line := range strings.Split(string(content), "\n") {
			f := strings.Split(line, ":")
			if len(f) < 7 || f[0] == "" {
				continue
			}
			uid, err1 := strconv.ParseUint(f[2], 10, 32)
			gid, err2 := strconv.ParseUint(f[3], 10, 32)
			if err1 != nil || err2 != nil {
				continue
			}
			a.users = append(a.users, account{name: f[0], uid: uint32(uid), gid: uint32(gid), home: f[5], shell: f[6]})
		}
	}
	a.groups = map[uint32]string{}
	if content, found := c.read("/etc/group", maxSmallFileBytes); found {
		for _, line := range strings.Split(string(content), "\n") {
			f := strings.Split(line, ":")
			if len(f) < 3 || f[0] == "" {
				continue
			}
			gid, err := strconv.ParseUint(f[2], 10, 32)
			if err != nil {
				continue
			}
			if _, dup := a.groups[uint32(gid)]; !dup {
				a.groups[uint32(gid)] = f[0]
			}
		}
	}
	return a
}

func (a accounts) byUID(uid uint32) (account, bool) {
	i := slices.IndexFunc(a.users, func(u account) bool { return u.uid == uid })
	if i < 0 {
		return account{}, false
	}
	return a.users[i], true
}

// agentUser describes the user the Collector runs as, which is the user the
// agent runs as. A name the host's files do not give is recorded as a Blind
// Spot, and the user or group is then named by its number.
func (c *collector) agentUser(a accounts) *snapshotv1.LinuxUser {
	p := c.h.Process()
	user := &snapshotv1.LinuxUser{Uid: p.UID}
	if u, ok := a.byUID(p.UID); ok {
		user.Name = u.name
	} else {
		user.Name = fmt.Sprintf("uid-%d", p.UID)
		c.blind(fmt.Sprintf("resolve the name of uid %d", p.UID), "no entry in /etc/passwd")
	}

	// The primary group comes first, then the others by GID.
	gids := slices.Clone(p.Groups)
	slices.Sort(gids)
	gids = slices.Compact(gids)
	gids = slices.DeleteFunc(gids, func(g uint32) bool { return g == p.GID })
	for _, gid := range append([]uint32{p.GID}, gids...) {
		name, ok := a.groups[gid]
		if !ok {
			name = fmt.Sprintf("gid-%d", gid)
			c.blind(fmt.Sprintf("resolve the name of gid %d", gid), "no entry in /etc/group")
		}
		user.Groups = append(user.Groups, &snapshotv1.LinuxGroup{Name: name, Gid: gid})
	}
	return user
}

// loginShell reports whether a shell lets someone log in. Accounts without
// one, such as daemons, do not hold an agent's credentials.
func loginShell(shell string) bool {
	switch path.Base(shell) {
	case "", "nologin", "false", "true", "sync", "shutdown", "halt":
		return false
	}
	return true
}
