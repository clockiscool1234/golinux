//go:build windows

package syscalls

import "golinux/internal/errno"

// Windows has no ioctl(2)/termios concept in this form at all -- no
// TCGETS, no struct winsize, no controlling-terminal process group.
// Every request this file's Unix build forwards to a real host
// ioctl(2) (see ioctl_unix.go) instead unconditionally fails here with
// ENOTTY, exactly the answer sysIoctl already gives for a non-stdio
// fd on every platform: "this isn't a terminal you can do that to".
// That's an honest simplification, not a broken feature -- a guest
// program's isatty(fd) (see this file's package doc comment for why
// that's the one thing ioctl() absolutely must get right) will report
// false for every fd when run under Windows, which is the same
// behavior a real Windows console gets from most POSIX layers anyway
// (full termios-style raw/cooked mode control, window-size queries,
// and TIOCSPGRP-style job control simply don't exist as the same
// concept there).
func hostIoctl(hostFd uintptr, request uint64, buf []byte) int {
	return errno.ENOTTY
}