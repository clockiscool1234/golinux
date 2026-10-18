//go:build linux

package syscalls

import (
	"syscall"
	"unsafe"
)

// hostIoctl forwards request to a real ioctl(2) on hostFd, reading the
// kernel's response into (or writing the guest's request from) buf in
// place -- see ioctl.go's sysIoctl for the get/set direction handling
// around this call. Returns 0 on success or a POSIX errno on failure
// (see the comment on the return statement for why that's safe to
// take directly from syscall.Errno here specifically).

func hostIoctl(hostFd uintptr, request uint64, buf []byte) int {
	_, _, errno1 := syscall.Syscall(syscall.SYS_IOCTL, hostFd, uintptr(request), uintptr(unsafe.Pointer(&buf[0])))
	// syscall.Errno's numeric value on a real Unix host IS the POSIX
	// errno the kernel returned (Go's syscall package defines Errno
	// as literally that number) -- safe to hand back directly, unlike
	// on Windows, where Errno wraps a totally different numbering
	// (Win32 system error codes) that would be meaningless as a
	// guest-facing POSIX errno; see ioctl_windows.go.
	return int(errno1)
}
