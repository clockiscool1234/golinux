//go:build windows

package syscalls

import "os"

// Windows has no POSIX process groups or sessions at all, so there's
// no real host call to forward these to the way process.go's Unix
// build (process_unix.go) forwards to the real kernel for job
// control. Reporting the host process's own pid as both the process
// group and session id, and treating every set-call as a trivial
// success, is the closest honest fiction available: every guest
// process in this emulator already shares that one real host process
// (see fork.go), so "the process group is a solitary group containing
// just this process" is at least self-consistent, and it means
// callers checking "is my pgid == my pid" (the common
// am-I-the-process-group-leader pattern shells use to decide whether
// to print job-control messages) get a sensible answer instead of a
// syscall that doesn't exist on this platform. Real job control
// (Ctrl-Z, background/foreground process groups) simply isn't
// available for a guest running under Windows -- that mirrors reality,
// since Windows consoles don't have an equivalent concept either.
func hostGetpgid(pid int) (int, error) { return os.Getpid(), nil }

func hostSetpgid(pid, pgid int) error { return nil }

func hostGetsid(pid int) (int, error) { return os.Getpid(), nil }

func hostSetsid() (int, error) { return os.Getpid(), nil }