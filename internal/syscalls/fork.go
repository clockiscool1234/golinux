// fork.go: execve() is implemented for real, in-place, and is safe.
// fork()/vfork()/clone()/wait4() are deliberately NOT implemented in
// this pass -- here's why, and what a real implementation needs.
//
// The Python original (sysemu/syscalls.py's _do_fork) calls the real
// host os.fork(2) and lets the child keep running as a genuinely
// separate OS process with copy-on-write memory. That works for
// CPython specifically because the GIL means only one native thread
// is ever executing Python bytecode at a time -- fork() only
// duplicates the calling OS thread, and CPython (mostly) tolerates
// that.
//
// Go does not get the same free pass. The Go runtime schedules
// goroutines across multiple OS threads it manages itself (GC
// workers, the sysmon thread, blocked syscall threads, etc.), and
// fork(2) only duplicates the *calling* thread -- every other thread
// simply doesn't exist in the child. If the child then does anything
// that needs the Go runtime's cooperation from those absent threads
// (allocate memory in a way that needs the GC, acquire a lock another
// (now-nonexistent) thread was holding, log, essentially "run normal
// Go code" -- and continuing CPU emulation absolutely requires all of
// that) it can deadlock unpredictably depending on what the other
// threads happened to be doing at the instant of fork(). This is a
// well-known, structural limitation, not a bug to be worked around
// with a clever syscall wrapper.
//
// The correct fix is a different design, not a direct port:
//
//   - Re-exec this same golinux binary as a real child *process*
//     (os/exec.Command, not syscall.Fork) positioned at the resumed
//     guest state, communicating the guest's memory/register snapshot
//     over a pipe or shared temp file. This gives genuine OS-level
//     process isolation and lets wait4() do a real os.exec-based
//     Wait() -- but it's a real subsystem (snapshot format, resume
//     protocol, host-fd inheritance rules) worth designing
//     deliberately rather than bolting on here.
//   - Alternatively, model fork() as an in-process "logical process"
//     (a second Process/Unicorn engine + fd table sharing this Go
//     process), trading real OS isolation for something achievable
//     without touching the fork(2) hazard at all -- cheaper to build,
//     but a blocking read() in the "child" would then stall the whole
//     emulator, which is exactly the problem the Python version's
//     comment says it moved away from.
//
// Until one of those lands, fork/vfork/clone report -ENOSYS (which is
// what a real, unprivileged-namespace-less Linux kernel would never
// do, but is an honest signal to the guest that this path isn't
// supported yet, rather than silently hanging), and wait4 reports
// -ECHILD since no child can ever exist.
package syscalls

import (
	"golinux/internal/consts"
	"golinux/internal/errno"
)

func init() {
	register(consts.SYS_execve, sysExecve)
	register(consts.SYS_fork, sysForkUnsupported)
	register(consts.SYS_vfork, sysForkUnsupported)
	register(consts.SYS_clone, sysCloneUnsupported)
	register(consts.SYS_wait4, sysWait4NoChildren)
}

func sysExecve(proc Proc, pathPtr, argvPtr, envpPtr, _, _, _ uint64) (int64, error) {
	path, ok := cstr(proc, pathPtr, 4096)
	if !ok || path == "" {
		return int64(-errno.ENOENT), nil
	}
	full := path
	if len(path) == 0 || path[0] != '/' {
		full = trimSlash(proc.Cwd()) + "/" + path
	}
	full = followSymlinks(proc, full)
	if !proc.VFS().Exists(full) {
		return int64(-errno.ENOENT), nil
	}
	meta, err := proc.VFS().GetMeta(full)
	if err != nil {
		return int64(-vfsErrno(err)), nil
	}
	if meta.Type != "reg" {
		return int64(-errno.EACCES), nil
	}

	argv := readCStrArray(proc, argvPtr)
	if len(argv) == 0 {
		argv = []string{path}
	}
	var envp []string
	if envpPtr != 0 {
		envp = readCStrArray(proc, envpPtr)
	}

	return 0, &Execve{Path: full, Argv: argv, Envp: envp}
}

func trimSlash(s string) string {
	for len(s) > 1 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

func sysForkUnsupported(proc Proc, _, _, _, _, _, _ uint64) (int64, error) {
	proc.Log("[fork] not supported: real fork() is unsafe under the Go runtime, see fork.go")
	return int64(-errno.ENOSYS), nil
}

const (
	cloneVM     = 0x00000100
	cloneThread = 0x00010000
)

func sysCloneUnsupported(proc Proc, flags, _, _, _, _, _ uint64) (int64, error) {
	proc.Log("[clone] not supported: real fork()/threading is unsafe under the Go runtime, see fork.go")
	return int64(-errno.ENOSYS), nil
}

func sysWait4NoChildren(proc Proc, _, _, _, _, _, _ uint64) (int64, error) {
	return int64(-errno.ECHILD), nil
}
