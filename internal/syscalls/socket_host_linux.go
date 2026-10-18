//go:build linux

package syscalls

import (
	"errors"
	"syscall"

	"golinux/internal/consts"
	"golinux/internal/errno"
)

func hostSocketClose(fd int) error { return syscall.Close(fd) }

func hostSocketRead(fd int, buf []byte) (int, error) { return syscall.Read(fd, buf) }

func hostSocketWrite(fd int, buf []byte) (int, error) { return syscall.Write(fd, buf) }

func hostSocketErrno(err error) int {
	var errno1 syscall.Errno
	if errors.As(err, &errno1) {
		return int(errno1)
	}
	return errno.EIO
}

func hostSocketGetFlags(g *GuestSocket) (uintptr, syscall.Errno) {
	ret, _, errno1 := syscall.Syscall(syscall.SYS_FCNTL, uintptr(g.f.fd), uintptr(consts.F_GETFL), 0)
	return ret, errno1
}

func hostSocketSetFlags(g *GuestSocket, flags int) syscall.Errno {
	_, _, errno1 := syscall.Syscall(syscall.SYS_FCNTL, uintptr(g.f.fd), uintptr(consts.F_SETFL), uintptr(flags&consts.O_NONBLOCK))
	return errno1
}

func hostAccept(fd int, flags uint64) (uintptr, syscall.Errno) {
	if flags == 0 {
		ret, _, errno1 := syscall.Syscall(syscall.SYS_ACCEPT, uintptr(fd), 0, 0)
		return ret, errno1
	}
	ret, _, errno1 := syscall.Syscall6(syscall.SYS_ACCEPT4, uintptr(fd), 0, 0, uintptr(flags), 0, 0)
	return ret, errno1
}
