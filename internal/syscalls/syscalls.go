// Package syscalls implements x86_64 Linux syscall handlers, ported
// from sysemu/syscalls.py.
//
// Each handler has the signature
//
//	func(proc Proc, a0, a1, a2, a3, a4, a5 uint64) (int64, error)
//
// where proc is the owning process (see the Proc interface below) and
// the return value is what goes into RAX -- a non-negative result, or
// -errno on failure, exactly like the real kernel. A non-nil error is
// only used for control-flow signals (Stop, Execve) that unwind out
// of the emulation loop; ordinary syscall failures are reported via
// -errno in the int64 return, never via error.
//
// Handlers are grouped into one file per category, named after the
// same grouping sysemu/syscalls.py uses in its section comments, so
// adding a new syscall means editing (or adding) one small,
// obviously-named file instead of a single 2000+ line one:
//
//	file.go     read/write/open/close/lseek/dup/fcntl/pipe/...
//	fs_meta.go  stat/fstat/access/chmod/chown/readlink/umask/...
//	dir.go      getcwd/chdir/mkdir/rmdir/rename/symlink/getdents64/...
//	memory.go   brk/mmap/munmap/mprotect
//	process.go  getpid/getuid/setuid/uname/sched_yield/...
//	time.go     gettimeofday/clock_gettime/nanosleep/getrandom
//	arch.go     arch_prctl/set_tid_address/set_robust_list/rseq
//	signal.go   rt_sigaction/rt_sigprocmask/kill/tgkill (stubs for now)
//	mount.go    mount/umount2/chroot/sethostname
//	misc.go     getrlimit/statfs/sync/flock/ftruncate/... (stubs)
//	fork.go     execve (real); fork/vfork/clone/wait4 (ENOSYS, see file)
//	exit.go     exit/exit_group
//	poll.go     poll/ppoll (real, host-fd-backed; select/pselect6 still stubbed)
//
// This pass covers real filesystem access, process/identity
// introspection, in-place execve(), and synthetic /proc and /dev
// content (see the procfs and devices packages, wired in via file.go
// and fs_meta.go). Not yet implemented, each for a specific reason
// documented in its would-be file:
//   - fork/vfork/clone/wait4: Go's runtime isn't fork-safe (see
//     fork.go) -- needs a different design than a direct port.
//   - Real signal delivery: needs the sigtramp/context-switch
//     machinery from sysemu/emulator.py, not yet ported.
//   - select/pselect6: same reasoning poll/ppoll used to fall under --
//     need real multiplexed I/O over the fd table for their fd_set
//     wire format; stubbed conservatively for now (see misc.go).
//     poll/ppoll themselves are implemented (see poll.go).
//   - sockets (socket/connect/bind/...): a whole subsystem on its
//     own; not started yet.
package syscalls

import (
	"fmt"

	"golinux/internal/consts"
	"golinux/internal/errno"
	"golinux/internal/fds"
	"golinux/internal/vfs"
)

// Stop is returned by exit/exit_group to unwind out of the run loop.
type Stop struct{ Code int }

func (s *Stop) Error() string { return fmt.Sprintf("process exited with code %d", s.Code) }

// Execve is returned by execve() to unwind out of the run loop so the
// caller (emulator.Process.Run) can rebuild the process image in
// place.
type Execve struct {
	Path string
	Argv []string
	Envp []string
}

func (e *Execve) Error() string { return "execve: " + e.Path }

// Fork is returned by fork()/vfork()/clone() (the process-shaped
// forms of clone -- see fork.go) to unwind out of onSyscall so
// internal/emulator's Process.onSyscall -- which owns the *cpu.Engine
// and can actually clone it -- can spawn the child. This package
// can't do that cloning itself: it only has the narrow, duck-typed
// Proc interface below, precisely to avoid importing internal/emulator
// (which would be a circular import, since emulator imports this
// package). See fork.go's doc comment for the overall design.
type Fork struct {
	// Vfork records that this came from vfork() (or a clone() call
	// with CLONE_VFORK set) purely for logging; see fork.go for why
	// it's otherwise handled identically to a plain fork().
	Vfork bool
}

func (f *Fork) Error() string { return "fork" }

// Proc is everything a syscall handler needs from the owning process.
// emulator.Process implements this; this package does not import the
// emulator package, avoiding a circular dependency (mirroring how
// sysemu/syscalls.py only ever receives a duck-typed `proc` object).
type Proc interface {
	MemRead(addr uint64, size int) ([]byte, error)
	MemWrite(addr uint64, data []byte) error

	Fds() *fds.Table
	VFS() *vfs.VFS
	SetVFS(*vfs.VFS) // used by chroot/pivot_root to swap the guest's view of "/"
	Pid() int
	Ppid() int
	Argv() []string
	BootTime() int64

	// Wait4 implements the wait4(2) syscall against this process's
	// children (see fork.go/emulator.Process.Wait4 for the child
	// registry fork() populates). It's a full Proc method rather than
	// a Fork-shaped control-flow signal because, unlike fork(), it
	// doesn't need engine-cloning access -- everything it needs
	// (the child registry, MemWrite for *wstatus) is already
	// reachable through Proc.
	Wait4(pid int64, wstatusPtr uint64, options int) (int64, error)

	Cwd() string
	SetCwd(path string)
	Umask() int
	SetUmask(newMask int) int // returns the OLD umask, like umask(2)
	Hostname() string
	SetHostname(string)

	Uid() uint32
	Gid() uint32
	Euid() uint32
	Egid() uint32
	Suid() uint32
	Sgid() uint32
	Fsuid() uint32
	Fsgid() uint32
	SetUid(uint32)
	SetGid(uint32)
	SetEuid(uint32)
	SetEgid(uint32)
	SetSuid(uint32)
	SetSgid(uint32)
	SetFsuid(uint32)
	SetFsgid(uint32)
	Groups() []uint32
	SetGroups([]uint32)

	Verbose() bool
	Log(msg string)

	DoBrk(addr uint64) uint64
	DoMmap(addr, length uint64, prot, flags, fd int, offset uint64) (uint64, error)
	DoMunmap(addr, length uint64) error
	DoMprotect(addr, length uint64, prot int) error

	SetFSBase(addr uint64)
	GetFSBase() uint64
}

// handlerFunc is the signature every syscall implementation has.
type handlerFunc func(proc Proc, a0, a1, a2, a3, a4, a5 uint64) (int64, error)

var table = map[int]handlerFunc{}

// register is called from each category file's init() to populate
// the dispatch table -- keeps every file self-contained (no shared
// table literal to merge-conflict over as more syscalls are added).
func register(num int, h handlerFunc) {
	if _, exists := table[num]; exists {
		panic(fmt.Sprintf("syscalls: duplicate registration for syscall %d", num))
	}
	table[num] = h
}

// Dispatch looks up and runs the handler for syscall number num.
// Returns the value to place in RAX, or a *Stop / *Execve error if
// the process is exiting or replacing its image.
func Dispatch(proc Proc, num int, a0, a1, a2, a3, a4, a5 uint64) (int64, error) {
	h, ok := table[num]
	if !ok {
		return sysUnimplemented(proc, num)
	}
	return h(proc, a0, a1, a2, a3, a4, a5)
}

func sysUnimplemented(proc Proc, num int) (int64, error) {
	name, ok := consts.SyscallNames[num]
	if !ok {
		name = fmt.Sprintf("sys_%d", num)
	}
	if proc.Verbose() {
		proc.Log(fmt.Sprintf("[unimplemented syscall] %s (%d)", name, num))
	}
	return int64(-errno.ENOSYS), nil
}
