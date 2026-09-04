// Package procfs implements a minimal synthetic /proc, ported from
// sysemu/procfs.py.
//
// This is intentionally NOT a real mount in the sense of moving bytes
// onto the host disk: /proc content is generated on the fly, per
// request, from live emulator state (the calling Proc plus the VFS's
// mount table). It only "exists" for paths that fall under wherever
// the guest has `mount -t proc proc /proc`'d -- see the syscalls
// package's procRel helper, which consults
// proc.VFS().MountType(path) == "proc" before routing here.
//
// Only a modest slice of the real /proc is modeled: enough for common
// shell/init idioms (`cat /proc/version`, `ps`, `/proc/self/...`,
// `/proc/mounts`) to work without erroring out. Anything else under
// /proc looks like ENOENT, same as a real kernel would for a /proc
// file it doesn't implement.
package procfs

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"golinux/internal/fds"
	"golinux/internal/vfs"
)

// Proc is everything procfs needs from the owning process. Defined
// here (rather than importing the syscalls or emulator package) to
// avoid a circular dependency -- syscalls imports procfs, not the
// other way around.
type Proc interface {
	Pid() int
	Argv() []string
	Cwd() string
	Hostname() string
	BootTime() int64
	Fds() *fds.Table
	VFS() *vfs.VFS
}

func staticText(proc Proc) map[string]string {
	boot := proc.BootTime()
	if boot == 0 {
		boot = time.Now().Unix()
	}
	uptime := float64(time.Now().Unix() - boot)
	if uptime < 0 {
		uptime = 0
	}
	return map[string]string{
		"version": "Linux version 6.6.0-emu (golinux@build) #1 SMP PREEMPT x86_64 GNU/Linux\n",
		"uptime":  fmt.Sprintf("%.2f %.2f\n", uptime, uptime),
		"loadavg": "0.00 0.00 0.00 1/1 1\n",
		"meminfo": "MemTotal:        2097152 kB\n" +
			"MemFree:         1048576 kB\n" +
			"MemAvailable:    1572864 kB\n" +
			"Buffers:               0 kB\n" +
			"Cached:            262144 kB\n" +
			"SwapTotal:              0 kB\n" +
			"SwapFree:               0 kB\n",
		"cpuinfo": "processor\t: 0\n" +
			"vendor_id\t: GenuineIntel\n" +
			"cpu family\t: 6\n" +
			"model name\t: golinux virtual CPU\n" +
			"cpu MHz\t\t: 2000.000\n" +
			"cache size\t: 8192 KB\n" +
			"flags\t\t: fpu sse sse2\n" +
			"bogomips\t: 4000.00\n\n",
		"stat": "cpu  0 0 0 0 0 0 0 0 0 0\n" +
			"cpu0 0 0 0 0 0 0 0 0 0 0\n" +
			"ctxt 0\n" +
			fmt.Sprintf("btime %d\n", boot) +
			"processes 1\n" +
			"procs_running 1\n" +
			"procs_blocked 0\n",
		"filesystems":          "nodev\tproc\nnodev\tsysfs\nnodev\tdevtmpfs\nnodev\ttmpfs\next4\n",
		"cmdline":              "BOOT_IMAGE=/init\x00",
		"sys/kernel/hostname":  proc.Hostname() + "\n",
		"sys/kernel/osrelease": "6.6.0-emu\n",
		"sys/kernel/ostype":    "Linux\n",
	}
}

func mountsText(proc Proc) string {
	var sb strings.Builder
	for _, m := range proc.VFS().MountsList() {
		fstype := m.Fstype
		if fstype == "" {
			fstype = "none"
		}
		fmt.Fprintf(&sb, "%s %s %s rw,relatime 0 0\n", m.Source, m.Path, fstype)
	}
	sb.WriteString("hostfs / hostfs rw,relatime 0 0\n")
	return sb.String()
}

func pidFiles(pid int, proc Proc) map[string]string {
	isSelf := pid == proc.Pid()
	argv := proc.Argv()
	if !isSelf {
		argv = []string{fmt.Sprintf("[pid %d]", pid)}
	}
	cmdline := ""
	name := "?"
	if len(argv) > 0 {
		cmdline = strings.Join(argv, "\x00") + "\x00"
		parts := strings.Split(argv[0], "/")
		name = parts[len(parts)-1]
		if len(name) > 15 {
			name = name[:15]
		}
	}
	ppid := 1
	if pid == 1 {
		ppid = 0
	}
	status := fmt.Sprintf("Name:\t%s\nState:\tR (running)\nPid:\t%d\nPPid:\t%d\n"+
		"Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n", name, pid, ppid)
	return map[string]string{
		"cmdline": cmdline,
		"status":  status,
		"comm":    name + "\n",
	}
}

// Exists reports whether relpath (relative to a proc mountpoint)
// names something this synthetic /proc models.
func Exists(relpath string, proc Proc) bool {
	_, _, ok := classify(relpath, proc)
	return ok
}

// IsDir reports whether relpath names a synthetic directory.
func IsDir(relpath string, proc Proc) bool {
	kind, _, ok := classify(relpath, proc)
	return ok && kind == "dir"
}

// IsSymlink reports whether relpath names a synthetic symlink.
func IsSymlink(relpath string, proc Proc) bool {
	kind, _, ok := classify(relpath, proc)
	return ok && kind == "lnk"
}

// Readlink resolves a synthetic symlink's target.
func Readlink(relpath string, proc Proc) (string, bool) {
	relpath = strings.Trim(relpath, "/")
	if relpath == "self" || relpath == "thread-self" {
		return strconv.Itoa(proc.Pid()), true
	}
	parts := strings.Split(relpath, "/")
	if len(parts) == 2 && parts[1] == "exe" {
		argv := proc.Argv()
		if len(argv) > 0 {
			return argv[0], true
		}
		return "/", true
	}
	if len(parts) == 2 && parts[1] == "cwd" {
		return proc.Cwd(), true
	}
	if len(parts) == 3 && parts[1] == "fd" {
		fd, err := strconv.Atoi(parts[2])
		if err != nil {
			return "", false
		}
		obj := proc.Fds().Get(fd)
		if obj == nil {
			return "", false
		}
		if gp := obj.GuestPath(); gp != "" {
			return gp, true
		}
		return fmt.Sprintf("pipe:[%d]", fd), true
	}
	return "", false
}

// Read returns the synthetic content of a regular /proc file.
func Read(relpath string, proc Proc) ([]byte, bool) {
	kind, payload, ok := classify(relpath, proc)
	if !ok || kind != "reg" {
		return nil, false
	}
	return []byte(payload), true
}

// Listdir lists the synthetic entries directly inside relpath.
func Listdir(relpath string, proc Proc) []string {
	if relpath == "" || relpath == "." {
		seen := map[string]bool{}
		for name := range staticText(proc) {
			seen[strings.SplitN(name, "/", 2)[0]] = true
		}
		top := make([]string, 0, len(seen))
		for n := range seen {
			top = append(top, n)
		}
		sort.Strings(top)
		return append(top, strconv.Itoa(proc.Pid()), "self", "mounts")
	}
	if relpath == "sys" {
		return []string{"kernel"}
	}
	if relpath == "sys/kernel" {
		return []string{"hostname", "osrelease", "ostype"}
	}
	if relpath == "self" || relpath == strconv.Itoa(proc.Pid()) {
		files := pidFiles(proc.Pid(), proc)
		out := make([]string, 0, len(files)+3)
		for n := range files {
			out = append(out, n)
		}
		sort.Strings(out)
		return append(out, "cwd", "exe", "fd")
	}
	if relpath == "self/fd" || relpath == strconv.Itoa(proc.Pid())+"/fd" {
		fds := proc.Fds().Entries()
		out := make([]string, 0, len(fds))
		for _, fd := range fds {
			out = append(out, strconv.Itoa(fd))
		}
		sort.Strings(out)
		return out
	}
	return nil
}

// classify returns (kind, payload, ok): kind is "reg"/"dir"/"lnk";
// payload is the file content for "reg" entries. ok is false if this
// path isn't something our synthetic /proc models.
func classify(relpath string, proc Proc) (string, string, bool) {
	relpath = strings.Trim(relpath, "/")
	if relpath == "" || relpath == "." {
		return "dir", "", true
	}
	if relpath == "mounts" {
		return "reg", mountsText(proc), true
	}
	static := staticText(proc)
	if payload, ok := static[relpath]; ok {
		return "reg", payload, true
	}
	if relpath == "sys" || relpath == "sys/kernel" {
		return "dir", "", true
	}
	parts := strings.Split(relpath, "/")
	if parts[0] == "self" || parts[0] == "thread-self" || isDigits(parts[0]) {
		pid := proc.Pid()
		if isDigits(parts[0]) {
			pid, _ = strconv.Atoi(parts[0])
		}
		if len(parts) == 1 {
			if parts[0] == "self" || parts[0] == "thread-self" {
				return "lnk", "", true
			}
			return "dir", "", true
		}
		sub := strings.Join(parts[1:], "/")
		if sub == "exe" || sub == "cwd" {
			return "lnk", "", true
		}
		if sub == "fd" {
			return "dir", "", true
		}
		if strings.HasPrefix(sub, "fd/") {
			fdStr := strings.TrimPrefix(sub, "fd/")
			fd, err := strconv.Atoi(fdStr)
			if err != nil || proc.Fds().Get(fd) == nil {
				return "", "", false
			}
			return "lnk", "", true
		}
		files := pidFiles(pid, proc)
		if payload, ok := files[sub]; ok {
			return "reg", payload, true
		}
		return "", "", false
	}
	return "", "", false
}

// Stat computes a synthetic struct-stat-like record for relpath,
// mirroring sysemu/procfs.py's _procfs_stat.
func Stat(relpath string, proc Proc) (vfs.Stat, bool) {
	now := time.Now().Unix()
	base := vfs.Stat{Uid: 0, Gid: 0, Mtime: now, Atime: now, Ctime: now, Rdev: 0}
	if IsDir(relpath, proc) {
		base.Mode = 0o040000 | 0o555 // S_IFDIR
		base.Nlink = 2
		return base, true
	}
	if IsSymlink(relpath, proc) {
		target, _ := Readlink(relpath, proc)
		base.Mode = 0o120000 | 0o777 // S_IFLNK
		base.Size = int64(len(target))
		base.Nlink = 1
		return base, true
	}
	data, ok := Read(relpath, proc)
	if !ok {
		return vfs.Stat{}, false
	}
	base.Mode = 0o100000 | 0o444 // S_IFREG
	base.Size = int64(len(data))
	base.Nlink = 1
	return base, true
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
