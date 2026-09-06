// ioctl.go implements the handful of ioctl(2) requests that actually
// matter for a guest program to behave correctly in an interactive
// terminal: the termios get/set pair (TCGETS/TCSETS*) and window-size
// get/set pair (TIOCGWINSZ/TIOCSWINSZ), plus the foreground-process-
// group pair (TIOCGPGRP/TIOCSPGRP) job control needs.
//
// ioctl() had no handler at all before this -- every call fell
// through to the generic "unimplemented syscall" path and returned
// ENOSYS unconditionally, for every fd and every request. That's a
// bigger problem than it looks: musl's (and glibc's) isatty(fd) is
// implemented as exactly one thing -- "does ioctl(fd, TCGETS, &buf)
// succeed?" -- so with ioctl() always failing, isatty() always
// returns false for every guest program, on every fd, unconditionally.
// That silently breaks anything that branches on "am I attached to a
// real terminal": interactive shells skip printing their prompt
// (ash/dash's classic behavior when isatty(0) is false), readline-like
// line editing and job control get disabled, and full-screen programs
// (less, vi) can't even ask for the terminal's size.
//
// The fix: for the three fds that can plausibly BE a real terminal --
// stdin/stdout/stderr, identified via fds.File.Name() the same way
// other special-cased syscalls already do -- forward these requests
// to the real underlying host fd (0/1/2, matching how internal/fds
// wires stdio straight to os.Stdin/Stdout/Stderr) with a real ioctl(2)
// syscall. If the host fd genuinely isn't a terminal either (output
// piped to a file, run non-interactively, etc.), the real kernel
// naturally returns ENOTTY, which is exactly the right answer to give
// the guest -- no separate "is this actually a tty" check needed here,
// the host kernel already knows.
//
// Every other fd (regular files, procfs, pipes, sockets) can't
// meaningfully answer a terminal ioctl at all; those keep falling
// through to ENOTTY without ever touching the host, since forwarding
// a real fd number that happens to collide with 0/1/2 by coincidence
// would be wrong.
package syscalls

import (
	"syscall"
	"unsafe"

	"golinux/internal/consts"
	"golinux/internal/errno"
)

func init() {
	register(consts.SYS_ioctl, sysIoctl)
}

// termiosSize is sizeof(struct termios) in the raw kernel ABI (used by
// TCGETS/TCSETS*) on linux/amd64: 4 tcflag_t fields (c_iflag, c_oflag,
// c_cflag, c_lflag), one cc_t c_line byte, and cc_t c_cc[19] -- 4*4 +
// 1 + 19 = 36 bytes. (This is the plain kernel struct termios, not
// glibc/musl's extended termios2 with ispeed/ospeed -- TCGETS never
// touches those.)
const termiosSize = 36

// winsizeSize is sizeof(struct winsize): 4 uint16 fields.
const winsizeSize = 8

// hostStdioFd maps a fds.File's special stdio name to the real host
// fd number it's wired to (see internal/fds' newStdin/newStdout/
// newStderr) -- the only fds a terminal ioctl can ever meaningfully
// apply to here.
func hostStdioFd(name string) (uintptr, bool) {
	switch name {
	case "stdin":
		return 0, true
	case "stdout":
		return 1, true
	case "stderr":
		return 2, true
	default:
		return 0, false
	}
}

func sysIoctl(proc Proc, fdNum, request, argPtr, _, _, _ uint64) (int64, error) {
	f := proc.Fds().Get(int(fdNum))
	if f == nil {
		return int64(-errno.EBADF), nil
	}
	hostFd, ok := hostStdioFd(f.Name())
	if !ok {
		// Not a stdio fd -- nothing on the host to forward a terminal
		// ioctl to. Every request this function handles is
		// terminal-specific, so ENOTTY (not ENOSYS) is the accurate
		// answer for a regular file/pipe/procfs entry, matching what
		// a real kernel would say for the exact same request against
		// a non-tty fd.
		switch request {
		case consts.TCGETS, consts.TCSETS, consts.TCSETSW, consts.TCSETSF,
			consts.TIOCGWINSZ, consts.TIOCSWINSZ, consts.TIOCGPGRP, consts.TIOCSPGRP:
			return int64(-errno.ENOTTY), nil
		}
		return sysUnimplemented(proc, int(consts.SYS_ioctl))
	}

	var bufSize int
	switch request {
	case consts.TCGETS, consts.TCSETS, consts.TCSETSW, consts.TCSETSF:
		bufSize = termiosSize
	case consts.TIOCGWINSZ, consts.TIOCSWINSZ:
		bufSize = winsizeSize
	case consts.TIOCGPGRP, consts.TIOCSPGRP:
		bufSize = 4 // pid_t
	default:
		return sysUnimplemented(proc, int(consts.SYS_ioctl))
	}

	isGet := request == consts.TCGETS || request == consts.TIOCGWINSZ || request == consts.TIOCGPGRP
	buf := make([]byte, bufSize)
	if !isGet {
		data, err := proc.MemRead(argPtr, bufSize)
		if err != nil {
			return int64(-errno.EFAULT), nil
		}
		copy(buf, data)
	}

	_, _, errno1 := syscall.Syscall(syscall.SYS_IOCTL, hostFd, uintptr(request), uintptr(unsafe.Pointer(&buf[0])))
	if errno1 != 0 {
		return int64(-int(errno1)), nil
	}

	if isGet {
		if err := proc.MemWrite(argPtr, buf); err != nil {
			return int64(-errno.EFAULT), nil
		}
	}
	return 0, nil
}
