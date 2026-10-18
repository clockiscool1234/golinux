//go:build !windows

package syscalls

import "syscall"

func hostGetpgid(pid int) (int, error) { return syscall.Getpgid(pid) }

func hostSetpgid(pid, pgid int) error { return syscall.Setpgid(pid, pgid) }

// hostGetsid isn't wrapped by the Go standard library on linux/amd64
// (unlike Getpgid/Setpgid/Setsid); go straight to the raw syscall
// number instead of pulling in golang.org/x/sys/unix for one call.
func hostGetsid(pid int) (int, error) {
	sid, _, errno1 := syscall.Syscall(syscall.SYS_GETSID, uintptr(pid), 0, 0)
	if errno1 != 0 {
		return 0, errno1
	}
	return int(sid), nil
}

func hostSetsid() (int, error) { return syscall.Setsid() }