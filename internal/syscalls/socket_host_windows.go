//go:build windows

package syscalls

import (
	"errors"
	"syscall"

	"golinux/internal/errno"
)

func hostSocketClose(fd int) error { return syscall.Closesocket(syscall.Handle(fd)) }

func hostSocketRead(fd int, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	wbuf := syscall.WSABuf{Len: uint32(len(buf)), Buf: &buf[0]}
	var read uint32
	var flags uint32
	err := syscall.WSARecv(syscall.Handle(fd), &wbuf, 1, &read, &flags, nil, nil)
	return int(read), err
}

func hostSocketWrite(fd int, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	wbuf := syscall.WSABuf{Len: uint32(len(buf)), Buf: &buf[0]}
	var written uint32
	err := syscall.WSASend(syscall.Handle(fd), &wbuf, 1, &written, 0, nil, nil)
	return int(written), err
}

func hostSocketErrno(err error) int {
	var errno1 syscall.Errno
	if !errors.As(err, &errno1) {
		return errno.EIO
	}
	switch uint32(errno1) {
	case 10004:
		return errno.EINTR
	case 10013:
		return errno.EACCES
	case 10014:
		return errno.EFAULT
	case 10022:
		return errno.EINVAL
	case 10024:
		return errno.EMFILE
	case 10035:
		return errno.EAGAIN
	case 10038:
		return errno.ENOTSOCK
	case 10041:
		return errno.EPROTOTYPE
	case 10043:
		return errno.EPROTONOSUPPORT
	case 10045:
		return errno.EOPNOTSUPP
	case 10047:
		return errno.EAFNOSUPPORT
	case 10048:
		return errno.EADDRINUSE
	case 10049:
		return errno.EADDRNOTAVAIL
	case 10050:
		return errno.ENETDOWN
	case 10051:
		return errno.ENETUNREACH
	case 10054:
		return errno.ECONNRESET
	case 10055:
		return errno.ENOBUFS
	case 10056:
		return errno.EISCONN
	case 10057:
		return errno.ENOTCONN
	case 10058:
		return errno.ESHUTDOWN
	case 10060:
		return errno.ETIMEDOUT
	case 10061:
		return errno.ECONNREFUSED
	default:
		return errno.EIO
	}
}

func hostSocketGetFlags(g *GuestSocket) (uintptr, syscall.Errno) {
	if g.f.nonblock {
		return ^uintptr(0), 0
	}
	return 0, 0
}

func hostSocketSetFlags(g *GuestSocket, flags int) syscall.Errno { return 0 }
