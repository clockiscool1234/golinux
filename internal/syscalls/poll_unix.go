//go:build !windows

package syscalls

import (
	"syscall"
	"unsafe"
)

// hostPoll forwards pfds (already filled in with real host fd numbers
// and requested events) to a real host poll(2), blocking this guest
// process's goroutine for up to waitMs milliseconds (0 means "return
// immediately", matching poll(2)'s own timeout=0 meaning) -- see
// poll.go's package doc comment for why blocking only this goroutine
// is exactly the right thing to do here. Each entry's revents field
// is filled in by the kernel in place. Returns 0 on success or a
// POSIX errno on failure (safe to take directly from syscall.Errno's
// numeric value here specifically -- see ioctl_unix.go's hostIoctl
// for why that doesn't hold on every platform).
func hostPoll(pfds []rawPollFd, waitMs int64) int {
	_, _, errno1 := syscall.Syscall(syscall.SYS_POLL,
		uintptr(unsafe.Pointer(&pfds[0])),
		uintptr(len(pfds)),
		uintptr(waitMs),
	)
	return int(errno1)
}