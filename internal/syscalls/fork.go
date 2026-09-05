// fork.go: execve() is implemented for real, in-place, and is safe.
// fork()/vfork()/clone() (the process-shaped calls -- see the
// CLONE_VM/CLONE_THREAD check below) and wait4() are now implemented
// too, via an in-process "logical process" design rather than a
// direct port of the Python original's real os.fork(2) call.
//
// Why not just call the real fork(2), like the Python original does?
// The Python original (sysemu/syscalls.py's _do_fork) can get away
// with it because CPython's GIL means only one native thread is ever
// executing Python bytecode at a time -- fork() only duplicates the
// calling OS thread, and CPython (mostly) tolerates that.
//
// Go does not get the same free pass. The Go runtime schedules
// goroutines across multiple OS threads it manages itself (GC
// workers, the sysmon thread, blocked syscall threads, etc.), and
// fork(2) only duplicates the *calling* thread -- every other thread
// simply doesn't exist in the child. If the child then does anything
// that needs the Go runtime's cooperation from those absent threads,
// it can deadlock unpredictably. This is a well-known, structural
// limitation of fork() under a multi-threaded runtime, not a bug to
// be worked around with a clever syscall wrapper -- so this port
// never calls the real fork(2) at all.
//
// What it does instead: since every "process" here is already just
// CPU state (registers + a page table) interpreted by a pure-Go
// engine (internal/cpu) rather than something the host kernel is
// actually scheduling, "forking" doesn't need the host kernel's
// fork() to begin with. fork() deep-copies the calling process's
// cpu.Engine (registers and every mapped page -- see cpu.Engine.Clone)
// and fd table (internal/fds.Table.Clone, which duplicates fd numbers
// but keeps them pointing at the same underlying Files, exactly
// matching real fork's shared-open-file-description semantics), gives
// the copy a new synthetic pid, and runs it forward on its own
// goroutine from internal/emulator.Process.onSyscall. Parent and
// child are then two independent goroutines, each running its own
// engine -- a blocking read() in the child blocks only that
// goroutine, never the parent or any other child, because Go's
// runtime already multiplexes blocking syscalls (made through the
// ordinary os package, which is all this codebase uses) onto extra OS
// threads on the child's behalf. That sidesteps the exact hazard
// above without needing the re-exec-based design floated in an
// earlier version of this comment: nothing here ever calls the real,
// unsafe fork(2).
//
// The actual clone-and-spawn logic lives in internal/emulator (see
// Process.onSyscall's handling of the *Fork return below, and
// Process.doFork) because it needs access to the *cpu.Engine this
// package's Proc interface deliberately doesn't expose. fork()/
// vfork() here just return a *Fork sentinel to signal that unwind;
// see Fork's doc comment in syscalls.go.
//
// Known simplifications, both safe (never wrong, just not a 1:1
// match for every corner of real semantics):
//   - vfork() is handled identically to fork(): a full, independent
//     copy rather than a shared address space with the parent
//     suspended until the child execs or exits. Real vfork() is
//     purely a performance optimization over fork() for the
//     fork()-then-immediately-exec() pattern shells use; giving every
//     vfork() a real fork()'s full copy is always correct, just not
//     as fast. The one observable difference -- a real vfork()'s
//     child can mutate the parent's memory before it execs/exits, and
//     the parent sees those mutations -- essentially never matters
//     for the fork()+exec() idiom this exists to serve.
//   - clone() only gets this treatment when its flags DON'T ask for a
//     shared address space or real OS-thread semantics (no CLONE_VM,
//     no CLONE_THREAD): that covers glibc/musl's fork() occasionally
//     routing through clone() instead of the plain fork syscall. A
//     clone() asking for real threading (pthread_create, which sets
//     both) still isn't implemented -- doing that properly needs
//     actual shared memory between logical processes plus real
//     scheduling semantics, a different (and larger) feature than
//     process-shaped fork. It reports ENOSYS, same as before.
//   - Guest pids handed out to fork() children are synthetic
//     (allocated by internal/emulator, not real host pids) -- see
//     that package's doc comment on why sysGetpgrp/sysGetpgid/
//     sysSetpgid/sysGetsid in process.go resolve "self" against the
//     real host pid rather than proc.Pid() as a result.
//   - If the root process exits while a forked child is still
//     running, that child's goroutine is abandoned along with the
//     rest of the Go process -- there's no init process here to
//     re-parent orphans to and keep them alive, unlike a real kernel.
package syscalls

import (
	"golinux/internal/consts"
	"golinux/internal/errno"
)

func init() {
	register(consts.SYS_execve, sysExecve)
	register(consts.SYS_fork, sysFork)
	register(consts.SYS_vfork, sysVfork)
	register(consts.SYS_clone, sysClone)
	register(consts.SYS_wait4, sysWait4)
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

// sysFork/sysVfork just signal the fork; internal/emulator.onSyscall
// does the actual cloning (see this file's package doc comment) and
// writes the real return value (the new child's pid, in the parent)
// once that's done -- the 0 returned here is never seen by the guest.
func sysFork(proc Proc, _, _, _, _, _, _ uint64) (int64, error) {
	return 0, &Fork{}
}

func sysVfork(proc Proc, _, _, _, _, _, _ uint64) (int64, error) {
	return 0, &Fork{Vfork: true}
}

const (
	cloneVM     = 0x00000100
	cloneVfork  = 0x00004000
	cloneThread = 0x00010000
)

// sysClone only handles the process-shaped case (see the package doc
// comment): no CLONE_VM, no CLONE_THREAD. Real thread creation
// (CLONE_VM|CLONE_THREAD, as pthread_create uses) isn't implemented.
func sysClone(proc Proc, flags, _, _, _, _, _ uint64) (int64, error) {
	if flags&(cloneVM|cloneThread) != 0 {
		proc.Log("[clone] not supported: real OS-thread semantics (CLONE_VM|CLONE_THREAD) aren't implemented, see fork.go")
		return int64(-errno.ENOSYS), nil
	}
	return 0, &Fork{Vfork: flags&cloneVfork != 0}
}

// sysWait4 delegates entirely to Proc.Wait4 -- see its doc comment in
// syscalls.go for why wait4, unlike fork, doesn't need a control-flow
// signal to reach into internal/emulator.
func sysWait4(proc Proc, pid, wstatusPtr, options, _, _, _ uint64) (int64, error) {
	return proc.Wait4(int64(int32(pid)), wstatusPtr, int(options))
}
