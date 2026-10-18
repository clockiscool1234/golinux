//go:build linux

// socket_impl.go holds the socket(2) syscall handlers themselves;
// socket.go holds the GuestSocket fds.File wrapper they all funnel
// through, plus the package doc comment explaining the host-backed
// design (split only so neither file grows unboundably).
//
// Raw-socket strategy: handlers issue raw host syscall numbers via
// syscall.Syscall (SYS_SOCKET/SYS_CONNECT/...) rather than the net
// package's Dial/Listen, because the guest hands us already-encoded
// sockaddr blobs and expects errno-shaped answers -- dialing with
// net.Dial would re-resolve hostnames and re-wrap errors, both of
// which are jobs this emulator leaves to the guest's own libc.

package syscalls

import (
	"encoding/binary"
	"runtime"
	"syscall"
	"unsafe"

	"golinux/internal/consts"
	"golinux/internal/errno"
)

// keepAlive pins a sockaddr/sockopt blob for the duration of the
// enclosing handler (the deferred call), since unsafe.Pointer usage
// below hands &blob[0] straight to the host kernel.
func keepAlive(b []byte) { runtime.KeepAlive(b) }

// hostSyscall invokes syscall n with up to six args, returning the
// raw return value and errno (0 on success). A thin named wrapper so
// each handler reads as "ask the host kernel" rather than a wall of
// syscall.Syscall6( arguments.
func hostSyscall(n uintptr, a ...uintptr) (uintptr, syscall.Errno) {
	var a1, a2, a3, a4, a5, a6 uintptr
	for i, v := range a {
		switch i {
		case 0:
			a1 = v
		case 1:
			a2 = v
		case 2:
			a3 = v
		case 3:
			a4 = v
		case 4:
			a5 = v
		case 5:
			a6 = v
		}
	}
	ret, _, errno1 := syscall.Syscall6(n, a1, a2, a3, a4, a5, a6)
	return ret, errno1
}

// guestDomain maps the guest AF_* to the host's identical value
// (every platform Go targets for this emulator shares Linux's
// AF numbering, which is itself the POSIX/BSD lineage), rejecting
// anything the host kernel would refuse to create for us.
func guestDomain(family uint64) (int, bool) {
	switch family {
	case consts.AF_INET, consts.AF_INET6, consts.AF_UNIX:
		return int(family), true
	default:
		return 0, false
	}
}

// sysSocket is socket(domain, type, protocol).
func sysSocket(proc Proc, domain, sockType, protocol, _, _, _ uint64) (int64, error) {
	fam, ok := guestDomain(domain)
	if !ok {
		return int64(-errno.EAFNOSUPPORT), nil
	}
	t := sockType & 0xff // strip SOCK_NONBLOCK/SOCK_CLOEXEC before the host sees it
	if t != consts.SOCK_STREAM && t != consts.SOCK_DGRAM {
		return int64(-errno.ESOCKTNOSUPPORT), nil
	}
	fd, e := hostSyscall(syscall.SYS_SOCKET, uintptr(fam), uintptr(t), uintptr(protocol))
	if e != 0 {
		return int64(-int(e)), nil
	}
	if debugHostFdLog != nil {
		debugHostFdLog(-int(fd)) // negative = "created", positive = "closed"
	}
	g := NewGuestSocket(int(fd), t == consts.SOCK_STREAM)
	if sockType&consts.SOCK_NONBLOCK_C != 0 {
		if e := hostSocketSetFlags(g, consts.O_NONBLOCK); e != 0 {
			_ = g.Close()
			return int64(-int(e)), nil
		}
		g.f.nonblock = true
	}
	gfd := proc.Fds().Alloc(g)
	if sockType&consts.SOCK_CLOEXEC_C != 0 {
		proc.Fds().SetCloexec(gfd, true)
	}
	return int64(gfd), nil
}

// sockAddr reads the guest's sockaddr blob (addrlen bytes at
// addrlenPtr's target address -- i.e. lenPtr points at a socklen_t).
// Returns the raw bytes, family, and length.
func readSockAddr(proc Proc, addrPtr, lenPtr uint64) ([]byte, uint16, int, bool) {
	if addrPtr == 0 || lenPtr == 0 {
		return nil, 0, 0, false
	}
	lenBuf, err := proc.MemRead(lenPtr, 4)
	if err != nil {
		return nil, 0, 0, false
	}
	addrlen := int(binary.LittleEndian.Uint32(lenBuf))
	if addrlen < 2 || addrlen > 128 {
		return nil, 0, 0, false
	}
	blob, err := proc.MemRead(addrPtr, addrlen)
	if err != nil {
		return nil, 0, 0, false
	}
	fam := binary.LittleEndian.Uint16(blob[0:2])
	return blob, fam, addrlen, true
}

// sysConnect is connect(fd, const struct sockaddr *addr, socklen_t addrlen).
func sysConnect(proc Proc, fdNum, addrPtr, addrlen, _, _, _ uint64) (int64, error) {
	g, ok := proc.Fds().Get(int(fdNum)).(*GuestSocket)
	if !ok {
		if proc.Fds().Get(int(fdNum)) == nil {
			return int64(-errno.EBADF), nil
		}
		return int64(-errno.ENOTSOCK), nil
	}
	if addrlen < 2 || addrlen > 128 {
		return int64(-errno.EINVAL), nil
	}
	blob, err := proc.MemRead(addrPtr, int(addrlen))
	if err != nil {
		return int64(-errno.EFAULT), nil
	}
	if _, ok := guestDomain(uint64(binary.LittleEndian.Uint16(blob[0:2]))); !ok {
		return int64(-errno.EAFNOSUPPORT), nil
	}
	_, e := hostSyscall(syscall.SYS_CONNECT, uintptr(g.f.fd), uintptr(unsafe.Pointer(&blob[0])), uintptr(addrlen))
	if e != 0 {
		return int64(-int(e)), nil
	}
	return 0, nil
}

// sysBind is bind(fd, addr, addrlen).
func sysBind(proc Proc, fdNum, addrPtr, addrlen, _, _, _ uint64) (int64, error) {
	g, ok := proc.Fds().Get(int(fdNum)).(*GuestSocket)
	if !ok {
		if proc.Fds().Get(int(fdNum)) == nil {
			return int64(-errno.EBADF), nil
		}
		return int64(-errno.ENOTSOCK), nil
	}
	if addrlen < 2 || addrlen > 128 {
		return int64(-errno.EINVAL), nil
	}
	blob, err := proc.MemRead(addrPtr, int(addrlen))
	if err != nil {
		return int64(-errno.EFAULT), nil
	}
	_, e := hostSyscall(syscall.SYS_BIND, uintptr(g.f.fd), uintptr(unsafe.Pointer(&blob[0])), uintptr(addrlen))
	runtime.KeepAlive(blob)
	if e != 0 {
		return int64(-int(e)), nil
	}
	return 0, nil
}

// sysListen is listen(fd, backlog).
func sysListen(proc Proc, fdNum, backlog, _, _, _, _ uint64) (int64, error) {
	g, ok := proc.Fds().Get(int(fdNum)).(*GuestSocket)
	if !ok {
		if proc.Fds().Get(int(fdNum)) == nil {
			return int64(-errno.EBADF), nil
		}
		return int64(-errno.ENOTSOCK), nil
	}
	_, e := hostSyscall(syscall.SYS_LISTEN, uintptr(g.f.fd), uintptr(backlog))
	if e != 0 {
		return int64(-int(e)), nil
	}
	return 0, nil
}

// sysAccept is accept(2)/accept4(2). The syscall number isn't
// distinguishable here (both were registered to this handler), so
// accept4's extra flags argument arrives in a4; only SOCK_CLOEXEC
// and SOCK_NONBLOCK (the two flags accept4(2) documents) are
// honored, in flags.
func sysAccept(proc Proc, fdNum, addrPtr, lenPtr, flags, _, _ uint64) (int64, error) {
	g, ok := proc.Fds().Get(int(fdNum)).(*GuestSocket)
	if !ok {
		if proc.Fds().Get(int(fdNum)) == nil {
			return int64(-errno.EBADF), nil
		}
		return int64(-errno.ENOTSOCK), nil
	}
	// accept4(2) when flags came in, else accept(2). Using SYS_ACCEPT4
	// with flags==0 is equivalent to accept(2), but SYS_ACCEPT4 isn't
	// available on every host Go builds for, so fall back cleanly.
	newfd, e := hostAccept(g.f.fd, flags)
	if e != 0 {
		return int64(-int(e)), nil
	}
	ng := NewGuestSocket(int(newfd), true)
	ng.f.nonblock = flags&consts.SOCK_NONBLOCK_C != 0
	ngfd := proc.Fds().Alloc(ng)
	if flags&consts.SOCK_CLOEXEC_C != 0 {
		proc.Fds().SetCloexec(ngfd, true)
	}
	// Fill in the peer address the caller asked for.
	if addrPtr != 0 && lenPtr != 0 {
		writePeerAddr(proc, int(newfd), addrPtr, lenPtr, syscall.SYS_GETPEERNAME)
	}
	return int64(ngfd), nil
}

// writePeerAddr queries the host socket's sockaddr via getsockname/
// getpeername and writes it out to addrPtr, updating *lenPtr. Failures
// are ignored (callers treat the address as best-effort, as the real
// kernel contract also permits: a truncated address still succeeds).
func writePeerAddr(proc Proc, hostFd int, addrPtr, lenPtr uint64, which uintptr) {
	lenBuf, err := proc.MemRead(lenPtr, 4)
	if err != nil {
		return
	}
	capLen := int(binary.LittleEndian.Uint32(lenBuf))
	if capLen < 2 || capLen > 128 {
		return
	}
	out := make([]byte, capLen)
	outLen := uint32(capLen)
	_, _, e := syscall.Syscall(which, uintptr(hostFd), uintptr(unsafe.Pointer(&out[0])), uintptr(unsafe.Pointer(&outLen)))
	if e != 0 {
		return
	}
	if outLen > uint32(capLen) {
		outLen = uint32(capLen)
	}
	if proc.MemWrite(addrPtr, out[:outLen]) != nil {
		return
	}
	lb := make([]byte, 4)
	binary.LittleEndian.PutUint32(lb, outLen)
	_ = proc.MemWrite(lenPtr, lb)
}

// sysGetsockname / sysGetpeername.
func sysGetsockname(proc Proc, fdNum, addrPtr, lenPtr, _, _, _ uint64) (int64, error) {
	g, ok := proc.Fds().Get(int(fdNum)).(*GuestSocket)
	if !ok {
		if proc.Fds().Get(int(fdNum)) == nil {
			return int64(-errno.EBADF), nil
		}
		return int64(-errno.ENOTSOCK), nil
	}
	writePeerAddr(proc, g.f.fd, addrPtr, lenPtr, syscall.SYS_GETSOCKNAME)
	return 0, nil
}

func sysGetpeername(proc Proc, fdNum, addrPtr, lenPtr, _, _, _ uint64) (int64, error) {
	g, ok := proc.Fds().Get(int(fdNum)).(*GuestSocket)
	if !ok {
		if proc.Fds().Get(int(fdNum)) == nil {
			return int64(-errno.EBADF), nil
		}
		return int64(-errno.ENOTSOCK), nil
	}
	writePeerAddr(proc, g.f.fd, addrPtr, lenPtr, syscall.SYS_GETPEERNAME)
	return 0, nil
}

// sysSendto is sendto(fd, buf, len, flags, dest_addr, addrlen).
// Plain send() is sendto with a null address, which is exactly how
// glibc/musl implement it, so this one handler covers both.
func sysSendto(proc Proc, fdNum, bufPtr, length, flags, addrPtr, addrlen uint64) (int64, error) {
	g, ok := proc.Fds().Get(int(fdNum)).(*GuestSocket)
	if !ok {
		if proc.Fds().Get(int(fdNum)) == nil {
			return int64(-errno.EBADF), nil
		}
		return int64(-errno.ENOTSOCK), nil
	}
	if length > uint64(^uint(0)>>1) {
		return int64(-errno.EINVAL), nil
	}
	data, err := proc.MemRead(bufPtr, int(length))
	if err != nil {
		return int64(-errno.EFAULT), nil
	}
	var dataPtr uintptr
	if len(data) > 0 {
		dataPtr = uintptr(unsafe.Pointer(&data[0]))
	}
	var destPtr uintptr
	var dest []byte
	if addrPtr != 0 {
		if addrlen < 2 || addrlen > 128 || addrlen > uint64(^uint(0)>>1) {
			return int64(-errno.EINVAL), nil
		}
		dest, err = proc.MemRead(addrPtr, int(addrlen))
		if err != nil {
			return int64(-errno.EFAULT), nil
		}
		destPtr = uintptr(unsafe.Pointer(&dest[0]))
	}
	n, e := hostSyscall(syscall.SYS_SENDTO, uintptr(g.f.fd), dataPtr, uintptr(len(data)), uintptr(flags), destPtr, uintptr(addrlen))
	runtime.KeepAlive(data)
	runtime.KeepAlive(dest)
	if e != 0 {
		return int64(-int(e)), nil
	}
	return int64(n), nil
}

// sysRecvfrom is recvfrom(fd, buf, len, flags, src_addr, addrlen).
// Plain recv() likewise arrives here with a null src_addr.
func sysRecvfrom(proc Proc, fdNum, bufPtr, length, flags, addrPtr, lenPtr uint64) (int64, error) {
	g, ok := proc.Fds().Get(int(fdNum)).(*GuestSocket)
	if !ok {
		if proc.Fds().Get(int(fdNum)) == nil {
			return int64(-errno.EBADF), nil
		}
		return int64(-errno.ENOTSOCK), nil
	}
	if length > uint64(^uint(0)>>1) {
		return int64(-errno.EINVAL), nil
	}
	if addrPtr != 0 && lenPtr == 0 {
		return int64(-errno.EFAULT), nil
	}
	buf := make([]byte, int(length))
	var bufPtrHost uintptr
	if len(buf) > 0 {
		bufPtrHost = uintptr(unsafe.Pointer(&buf[0]))
	}
	var src [128]byte
	var srcLen uint32
	var srcPtr, srcLenPtr uintptr
	if addrPtr != 0 {
		lenBuf, err := proc.MemRead(lenPtr, 4)
		if err != nil {
			return int64(-errno.EFAULT), nil
		}
		guestSrcLen := binary.LittleEndian.Uint32(lenBuf)
		srcLen = guestSrcLen
		if srcLen > uint32(len(src)) {
			srcLen = uint32(len(src))
		}
		srcPtr = uintptr(unsafe.Pointer(&src[0]))
		srcLenPtr = uintptr(unsafe.Pointer(&srcLen))
	}
	n, e := hostSyscall(syscall.SYS_RECVFROM, uintptr(g.f.fd), bufPtrHost, uintptr(len(buf)), uintptr(flags), srcPtr, srcLenPtr)
	runtime.KeepAlive(buf)
	runtime.KeepAlive(src)
	runtime.KeepAlive(&srcLen)
	if e != 0 {
		return int64(-int(e)), nil
	}
	writeLen := len(buf)
	if n < uintptr(writeLen) {
		writeLen = int(n)
	}
	if writeLen > 0 {
		if err := proc.MemWrite(bufPtr, buf[:writeLen]); err != nil {
			return int64(-errno.EFAULT), nil
		}
	}
	if addrPtr != 0 {
		addrWriteLen := int(srcLen)
		if addrWriteLen > len(src) {
			addrWriteLen = len(src)
		}
		guestSrcLen, err := proc.MemRead(lenPtr, 4)
		if err != nil {
			return int64(-errno.EFAULT), nil
		}
		guestCap := int(binary.LittleEndian.Uint32(guestSrcLen))
		if addrWriteLen > guestCap {
			addrWriteLen = guestCap
		}
		if addrWriteLen > 0 {
			if err := proc.MemWrite(addrPtr, src[:addrWriteLen]); err != nil {
				return int64(-errno.EFAULT), nil
			}
		}
		outLen := make([]byte, 4)
		binary.LittleEndian.PutUint32(outLen, srcLen)
		if err := proc.MemWrite(lenPtr, outLen); err != nil {
			return int64(-errno.EFAULT), nil
		}
	}
	return int64(n), nil
}

// sysShutdown is shutdown(fd, how).
func sysShutdown(proc Proc, fdNum, how, _, _, _, _ uint64) (int64, error) {
	g, ok := proc.Fds().Get(int(fdNum)).(*GuestSocket)
	if !ok {
		if proc.Fds().Get(int(fdNum)) == nil {
			return int64(-errno.EBADF), nil
		}
		return int64(-errno.ENOTSOCK), nil
	}
	if how > consts.SHUT_RDWR {
		return int64(-errno.EINVAL), nil
	}
	_, e := hostSyscall(syscall.SYS_SHUTDOWN, uintptr(g.f.fd), uintptr(how))
	if e != 0 {
		return int64(-int(e)), nil
	}
	return 0, nil
}

// sysSocketpair is socketpair(domain, type, protocol, sv).
func sysSocketpair(proc Proc, domain, sockType, protocol, svPtr, _, _ uint64) (int64, error) {
	fam, ok := guestDomain(domain)
	if !ok {
		return int64(-errno.EAFNOSUPPORT), nil
	}
	t := sockType & 0xff
	var sv [2]int32
	_, e := hostSyscall(syscall.SYS_SOCKETPAIR, uintptr(fam), uintptr(t), uintptr(protocol), uintptr(unsafe.Pointer(&sv[0])))
	if e != 0 {
		return int64(-int(e)), nil
	}
	g0 := NewGuestSocket(int(sv[0]), t == consts.SOCK_STREAM)
	g1 := NewGuestSocket(int(sv[1]), t == consts.SOCK_STREAM)
	if debugHostFdLog != nil {
		debugHostFdLog(-int(sv[0]))
		debugHostFdLog(-int(sv[1]))
	}
	fd0 := proc.Fds().Alloc(g0)
	fd1 := proc.Fds().Alloc(g1)
	if sockType&consts.SOCK_NONBLOCK_C != 0 {
		if e := hostSocketSetFlags(g0, consts.O_NONBLOCK); e != 0 {
			_ = g0.Close()
			_ = g1.Close()
			return int64(-int(e)), nil
		}
		if e := hostSocketSetFlags(g1, consts.O_NONBLOCK); e != 0 {
			_ = g0.Close()
			_ = g1.Close()
			return int64(-int(e)), nil
		}
		g0.f.nonblock = true
		g1.f.nonblock = true
	}
	out := make([]byte, 8)
	binary.LittleEndian.PutUint32(out[0:4], uint32(fd0))
	binary.LittleEndian.PutUint32(out[4:8], uint32(fd1))
	if err := proc.MemWrite(svPtr, out); err != nil {
		return int64(-errno.EFAULT), nil
	}
	return 0, nil
}

// sysSetsockopt is setsockopt(fd, level, optname, optval, optlen).
// The option blob is forwarded verbatim to the host kernel: the
// guest's SOL_SOCKET/SO_* numbering matches the host's on every
// platform this emulator builds for, and non-SOL_SOCKET levels pass
// straight through to the same host protocol stacks the real guest
// kernel would consult.
func sysSetsockopt(proc Proc, fdNum, level, optname, optvalPtr, optlen, _ uint64) (int64, error) {
	g, ok := proc.Fds().Get(int(fdNum)).(*GuestSocket)
	if !ok {
		if proc.Fds().Get(int(fdNum)) == nil {
			return int64(-errno.EBADF), nil
		}
		return int64(-errno.ENOTSOCK), nil
	}
	if optlen > 0 {
		blob, err := proc.MemRead(optvalPtr, int(optlen))
		if err != nil {
			return int64(-errno.EFAULT), nil
		}
		defer keepAlive(blob)
		_, e := hostSyscall(syscall.SYS_SETSOCKOPT, uintptr(g.f.fd), uintptr(level), uintptr(optname), uintptr(unsafe.Pointer(&blob[0])), uintptr(optlen))
		if e != 0 {
			return int64(-int(e)), nil
		}
		return 0, nil
	}
	_, e := hostSyscall(syscall.SYS_SETSOCKOPT, uintptr(g.f.fd), uintptr(level), uintptr(optname), 0, 0)
	if e != 0 {
		return int64(-int(e)), nil
	}
	return 0, nil
}

// sysGetsockopt is getsockopt(fd, level, optname, optval, optlen).
// SO_ERROR is intercepted and re-answered as 0 (success) rather than
// passed to the host: connect(2) failures in this emulator surface
// synchronously as negative returns from sysConnect, so a subsequent
// SO_ERROR poll must not resurrect the stale host errno.
func sysGetsockopt(proc Proc, fdNum, level, optname, optvalPtr, optlenPtr, _ uint64) (int64, error) {
	g, ok := proc.Fds().Get(int(fdNum)).(*GuestSocket)
	if !ok {
		if proc.Fds().Get(int(fdNum)) == nil {
			return int64(-errno.EBADF), nil
		}
		return int64(-errno.ENOTSOCK), nil
	}
	if level == consts.SOL_SOCKET && optname == consts.SO_ERROR {
		if optlenPtr == 0 {
			return int64(-errno.EFAULT), nil
		}
		lb := make([]byte, 4)
		binary.LittleEndian.PutUint32(lb, 4)
		if err := proc.MemWrite(optlenPtr, lb); err != nil {
			return int64(-errno.EFAULT), nil
		}
		if optvalPtr != 0 {
			zb := make([]byte, 4)
			if err := proc.MemWrite(optvalPtr, zb); err != nil {
				return int64(-errno.EFAULT), nil
			}
		}
		return 0, nil
	}
	lenBuf, err := proc.MemRead(optlenPtr, 4)
	if err != nil {
		return int64(-errno.EFAULT), nil
	}
	outLen := uint32(binary.LittleEndian.Uint32(lenBuf))
	if outLen == 0 || outLen > 1024 {
		return int64(-errno.EINVAL), nil
	}
	out := make([]byte, outLen)
	_, _, e := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(g.f.fd), uintptr(level), uintptr(optname), uintptr(unsafe.Pointer(&out[0])), uintptr(unsafe.Pointer(&outLen)), 0)
	if e != 0 {
		return int64(-int(e)), nil
	}
	if err := proc.MemWrite(optvalPtr, out[:outLen]); err != nil {
		return int64(-errno.EFAULT), nil
	}
	binary.LittleEndian.PutUint32(lenBuf, outLen)
	if err := proc.MemWrite(optlenPtr, lenBuf); err != nil {
		return int64(-errno.EFAULT), nil
	}
	return 0, nil
}

// sysSendmsg is sendmsg(fd, const struct msghdr *msg, flags). musl's
// DNS resolver reads its UDP answers with recvmsg() (it wants the
// ancillary-msgname source address to tell which nameserver replied),
// and writes queries via sendto -- so sendmsg stays ENOSYS (nothing
// exercised here calls it: plain sockets use sendto) while recvmsg
// gets a real implementation below, covering exactly the fields musl
// touches: one iovec, msg_name, msg_namelen, and msg_flags; the
// msg_control ancillary buffer is not filled (musl only reads
// MSG_TRUNC/MSG_CTRUNC from msg_flags, never the cmsg data, for UDP).
func sysSendmsg(proc Proc, fdNum, msgPtr, flags, _, _, _ uint64) (int64, error) {
	return int64(-errno.ENOSYS), nil
}

// msghdr is struct msghdr on linux/amd64, as the guest lays it out:
//
//	void *msg_name       (8)   optional sockaddr
//	socklen_t msg_namelen(4) + 4 pad
//	struct iovec *msg_iov(8)   scatter-gather array
//	size_t msg_iovlen    (8)   its length
//	void *msg_control    (8)   ancillary data
//	size_t msg_controllen(8)
//	int msg_flags        (4) + 4 pad
//
// = 56 bytes total.
const msghdrSize = 56

// iovecSize is sizeof(struct iovec): 8-byte base + 8-byte len.
const iovecSize = 16

// sysRecvmsg is recvmsg(fd, struct msghdr *msg, flags).
func sysRecvmsg(proc Proc, fdNum, msgPtr, flags, _, _, _ uint64) (int64, error) {
	g, ok := proc.Fds().Get(int(fdNum)).(*GuestSocket)
	if !ok {
		if proc.Fds().Get(int(fdNum)) == nil {
			return int64(-errno.EBADF), nil
		}
		return int64(-errno.ENOTSOCK), nil
	}
	hdr, err := proc.MemRead(msgPtr, msghdrSize)
	if err != nil {
		return int64(-errno.EFAULT), nil
	}
	msgName := binary.LittleEndian.Uint64(hdr[0:8])
	msgNamelen := binary.LittleEndian.Uint32(hdr[8:12])
	iovPtr := binary.LittleEndian.Uint64(hdr[16:24])
	iovLen := binary.LittleEndian.Uint64(hdr[24:32])

	// Gather the caller's iovecs into one flat read buffer (a real
	// kernel fills them in order; flattening is indistinguishable to
	// the caller as long as lengths add up, which they do).
	var total int
	for i := 0; i < int(iovLen) && i < 1024; i++ {
		base := iovPtr + uint64(i*iovecSize)
		lens, err := proc.MemRead(base+8, 8)
		if err != nil {
			return int64(-errno.EFAULT), nil
		}
		total += int(binary.LittleEndian.Uint64(lens))
	}
	if total < 0 || total > 1<<20 {
		return int64(-errno.EMSGSIZE), nil
	}
	buf := make([]byte, total)
	var bufPtr uintptr
	if len(buf) > 0 {
		bufPtr = uintptr(unsafe.Pointer(&buf[0]))
	}
	var src [128]byte
	srcLen := uint32(len(src))
	var srcPtr uintptr
	if msgName != 0 {
		srcPtr = uintptr(unsafe.Pointer(&src[0]))
	}
	n, e := hostSyscall(syscall.SYS_RECVFROM, uintptr(g.f.fd), bufPtr, uintptr(len(buf)), uintptr(flags), srcPtr, uintptr(unsafe.Pointer(&srcLen)))
	runtime.KeepAlive(buf)
	runtime.KeepAlive(src)
	runtime.KeepAlive(&srcLen)
	if e != 0 {
		return int64(-int(e)), nil
	}
	if int64(n) > int64(len(buf)) {
		n = uintptr(len(buf))
	}
	// Scatter the received bytes back out across the iovecs.
	remaining := int(n)
	for i := 0; i < int(iovLen) && remaining > 0; i++ {
		base := iovPtr + uint64(i*iovecSize)
		ihdr, err := proc.MemRead(base, iovecSize)
		if err != nil {
			return int64(-errno.EFAULT), nil
		}
		dst := binary.LittleEndian.Uint64(ihdr[0:8])
		l := int(binary.LittleEndian.Uint64(ihdr[8:16]))
		if l > remaining {
			l = remaining
		}
		if err := proc.MemWrite(dst, buf[:l]); err != nil {
			return int64(-errno.EFAULT), nil
		}
		remaining -= l
	}
	// Fill msg_name/msg_namelen (the reply's source address) and zero
	// msg_flags -- none of MSG_TRUNC/MSG_CTRUNC/etc. apply to the
	// plain reads musl does here.
	if msgName != 0 && srcLen > 0 {
		writeLen := uint64(srcLen)
		if writeLen > uint64(msgNamelen) {
			writeLen = uint64(msgNamelen)
		}
		if writeLen > 0 {
			if err := proc.MemWrite(msgName, src[:writeLen]); err != nil {
				return int64(-errno.EFAULT), nil
			}
		}
	}
	binary.LittleEndian.PutUint32(hdr[8:12], srcLen)
	binary.LittleEndian.PutUint32(hdr[48:52], 0) // msg_flags
	if err := proc.MemWrite(msgPtr, hdr); err != nil {
		return int64(-errno.EFAULT), nil
	}
	return int64(n), nil
}
