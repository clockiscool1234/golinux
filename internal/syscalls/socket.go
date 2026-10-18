// socket.go implements the socket(2) family, host-backed: every
// guest socket IS a real host socket (created via Go's syscall/
// net packages), wrapped as a fds.File so it lands in the normal fd
// table. That's the same "forward to the real host fd" strategy
// ioctl.go and poll.go already use for stdio and pipes, and it buys
// this file the same two properties those rely on: real, honest
// blocking/timeout semantics without any event-loop machinery, and
// automatic poll(2) support -- a guest socket's Read blocks only its
// own goroutine, exactly like a real blocking socket blocks only its
// calling thread, and poll.go's hostFdForFile forwards socket fds to
// the host poll(2) alongside pipes and stdio.
//
// What's covered: socket, connect, bind, listen, accept/accept4,
// sendto/recvfrom (and plain send/recv, which the libc layers
// implement as sendto/recvfrom with null sockaddr anyway), shutdown,
// getsockname/getpeername, setsockopt/getsockopt, and socketpair.
// sendmsg/recvmsg are registered but ENOSYS: nothing exercised so
// far (musl's DNS resolver, apk's HTTP) needs scatter-gather or
// real ancillary data, and the msghdr wire format is a whole file
// on its own; see the comment on sysSendmsg.
//
// sockaddr translation: the guest hands us raw sockaddr blobs in
// guest memory (family little-endian 16-bit first, then the
// family-specific bytes, exactly the wire format a real kernel
// copies in). AF_INET/AF_INET6/AF_UNIX layouts are identical
// between this emulator's x86_64 guests and every host Go targets
// here, so the blob is passed through byte-for-byte after family
// validation. getsockname/getpeername write the host's sockaddr back
// out in the same wire format, so no translation layer is needed
// anywhere -- a deliberate narrowness: anything exotic (AF_NETLINK
// mostly) returns EAFNOSUPPORT rather than pretending.
package syscalls

// sysSendmsg / sysRecvmsg live in socket_impl.go along with every
// other socket(2) handler; this file carries only the GuestSocket
// fds.File wrapper. See that file (and this package's doc comment in
// syscalls.go) for the host-backed design.

import (
	"syscall"

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
	if g.f.fd >= 0 {
		if debugHostFdLog != nil {
			debugHostFdLog(g.f.fd)
		}
		return syscall.Close(g.f.fd)
	}
	return nil
}

func (g *GuestSocket) Read(n int) ([]byte, error) {
	if n <= 0 {
		return nil, nil
	}
	buf := make([]byte, n)
	k, err := syscall.Read(g.f.fd, buf)
	if k > 0 {
		return buf[:k], nil
	}
	if err != nil {
		if err == syscall.EINTR {
			return nil, nil
		}
		if err == syscall.EAGAIN && g.f.nonblock {
			// Signal EAGAIN to the guest rather than a 0-byte read:
			// the fds.File Read contract has no other way to express
			// "nothing ready yet", and callers like busybox wget treat
			// a 0 return as EOF, which would end a transfer that
			// simply hadn't drained the pipe/socket yet (see
			// sysRead/sysReadv's errno extraction).
			return nil, &fds.ErrnoError{Errno: errno.EAGAIN}
		}
		return nil, err
	}
	return nil, nil // EOF
}

func (g *GuestSocket) Write(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	k, err := syscall.Write(g.f.fd, data)
	if k < 0 {
		k = 0
	}
	if err != nil && err != syscall.EINTR {
		if err == syscall.EAGAIN && g.f.nonblock {
			return 0, nil
		}
		return k, err
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
	if errno1, ok := err.(syscall.Errno); ok {
		return int(errno1)
	}
	return errno.EIO
}
