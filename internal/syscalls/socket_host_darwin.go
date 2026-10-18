//go:build darwin

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
	if !errors.As(err, &errno1) {
		return errno.EIO
	}
	switch int(errno1) {
	case 4:
		return errno.EINTR
	case 35:
		return errno.EAGAIN
	case 48:
		return errno.EADDRINUSE
	case 49:
		return errno.EADDRNOTAVAIL
	case 61:
		return errno.ECONNREFUSED
	case 54:
		return errno.ECONNRESET
	case 60:
		return errno.ETIMEDOUT
	default:
		return int(errno1)
	}
}

func hostSocketGetFlags(g *GuestSocket) (uintptr, syscall.Errno) {
	if g.f.nonblock {
		return uintptr(consts.O_NONBLOCK), 0
	}
	return 0, 0
}

func hostSocketSetFlags(g *GuestSocket, flags int) syscall.Errno { return 0 }
