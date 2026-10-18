// socket.go holds the GuestSocket file-descriptor wrapper. Linux
// provides the host-backed socket(2) implementation; macOS and
// Windows currently build and run the emulator with socket syscalls
// returning ENOSYS (see socket_impl_stub.go).
//
// What's covered: socket, connect, bind, listen, accept/accept4,
// sendto/recvfrom (and plain send/recv, which the libc layers
// implement as sendto/recvfrom with null sockaddr anyway), shutdown,
// getsockname/getpeername, setsockopt/getsockopt, and socketpair.
// sendmsg remains ENOSYS; recvmsg supports the one-iovec/name fields
// used by musl's DNS resolver, but does not populate ancillary data.
//
// On Linux, guest sockaddr blobs use the host kernel's Linux x86-64
// layout and are passed through byte-for-byte after family validation.
package syscalls

// sysSendmsg / sysRecvmsg live in socket_impl.go along with every
// other socket(2) handler; this file carries only the GuestSocket
// fds.File wrapper. See that file (and this package's doc comment in
// syscalls.go) for the host-backed design.

import (
	"golinux/internal/consts"
	"golinux/internal/errno"
	"golinux/internal/fds"
)

func init() {
	register(consts.SYS_socket, sysSocket)
	register(consts.SYS_connect, sysConnect)
	register(consts.SYS_bind, sysBind)
	register(consts.SYS_listen, sysListen)
	register(consts.SYS_accept, sysAccept)
	register(consts.SYS_accept4, sysAccept)
	register(consts.SYS_sendto, sysSendto)
	register(consts.SYS_recvfrom, sysRecvfrom)
	register(consts.SYS_sendmsg, sysSendmsg)
	register(consts.SYS_recvmsg, sysRecvmsg)
	register(consts.SYS_shutdown, sysShutdown)
	register(consts.SYS_getsockname, sysGetsockname)
	register(consts.SYS_getpeername, sysGetpeername)
	register(consts.SYS_socketpair, sysSocketpair)
	register(consts.SYS_setsockopt, sysSetsockopt)
	register(consts.SYS_getsockopt, sysGetsockopt)
}

// GuestSocket is a fds.File wrapping one real host socket. It lives
// in this package (not internal/fds) so poll.go/hostFdForFile can
// type-assert it -- mirroring how pipeEnd lives with the pipe
// syscalls in file.go.
type GuestSocket struct {
	f *netFD
}

// netFD is the raw-host-fd handle GuestSocket owns.
type netFD struct {
	// fd is the raw host descriptor. -1 means "closed" (Close sets
	// it); 0 is a legal real fd, so the sentinel must not be 0.
	fd       int
	nonblock bool
}

var debugHostFdLog func(fd int)

func SetDebugHostFdLog(f func(fd int)) { debugHostFdLog = f }

// NewGuestSocket exposes the socket constructor to any other
// package that needs to hand a real host socket to the guest (the
// way devices.NewStreamDev lets other packages build pseudo-devices
// without importing fds internals).
func NewGuestSocket(hostFd int, stream bool) *GuestSocket {
	// stream is recorded nowhere for now: it exists so future
	// datagram-vs-stream special cases have an obvious hook, and so
	// call sites read as "make a socket" rather than "wrap an fd".
	_ = stream
	return &GuestSocket{f: &netFD{fd: hostFd}}
}

func (g *GuestSocket) Name() string      { return "socket" }
func (g *GuestSocket) GuestPath() string { return "" }
func (g *GuestSocket) IsDir() bool       { return false }
func (g *GuestSocket) Close() error {
	if g.f.fd < 0 {
		return nil
	}
	fd := g.f.fd
	g.f.fd = -1
	if debugHostFdLog != nil {
		debugHostFdLog(fd)
	}
	return hostSocketClose(fd)
}

func (g *GuestSocket) Read(n int) ([]byte, error) {
	if n <= 0 {
		return nil, nil
	}
	buf := make([]byte, n)
	k, err := hostSocketRead(g.f.fd, buf)
	if k > 0 {
		return buf[:k], nil
	}
	if err != nil {
		guestErrno := hostSocketErrno(err)
		if guestErrno == errno.EAGAIN && g.f.nonblock {
			return nil, &fds.ErrnoError{Errno: errno.EAGAIN}
		}
		return nil, &fds.ErrnoError{Errno: guestErrno}
	}
	return nil, nil
}

func (g *GuestSocket) Write(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	k, err := hostSocketWrite(g.f.fd, data)
	if k < 0 {
		k = 0
	}
	if err != nil {
		guestErrno := hostSocketErrno(err)
		return k, &fds.ErrnoError{Errno: guestErrno}
	}
	return k, nil
}

// hostFd lets poll.go forward this socket to a real host poll(2).
func (g *GuestSocket) hostFd() int { return g.f.fd }

// syscallErrno maps a Go error from the syscall/net packages to the
// guest-facing POSIX errno. syscall.Errno's numeric value IS the
// host's POSIX errno (see ioctl_unix.go for why that's safe here and
// not on Windows); net.OpError and friends get unwrapped first.
func syscallErrno(err error) int {
	if err == nil {
		return 0
	}
	if unwrapped, ok := err.(interface{ Unwrap() error }); ok {
		if inner := unwrapped.Unwrap(); inner != nil {
			return syscallErrno(inner)
		}
	}
	return hostSocketErrno(err)
}
