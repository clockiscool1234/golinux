// poll.go implements poll(2) and ppoll(2) -- previously both were
// unconditionally ENOSYS (see syscalls.go's package doc comment and
// the note that used to live in misc.go), which broke every
// interactive shell's line editor: busybox ash calls poll() on stdin
// before every read and, on ENOSYS, logs "sh: poll: Function not
// implemented" once per prompt. select()/pselect6() are NOT covered
// here and remain ENOSYS -- same reasoning as before (they'd need the
// same host-fd-aware plumbing this file adds, just for a different
// wire format; left for a follow-up pass since nothing exercised so
// far needs them).
//
// The key realization that makes a real (not fake-always-ready)
// implementation safe here: since internal/emulator gives every guest
// process its own goroutine (see fork.go's package doc comment),
// blocking *this* goroutine in a real, honest host poll() -- for as
// long as the guest asked for, including forever -- blocks only that
// one guest process, exactly matching what a real blocking poll(2)
// does. That's different from sysNanosleep's deliberate no-op (see
// time.go): nanosleep never got revisited after the goroutine-per-
// process redesign, but poll needs a real wait to be useful at all
// (a shell blocked on "wait for a keypress" that returns immediately
// forever would spin its prompt loop instead of waiting), so it gets
// the real thing here.
//
// Only two kinds of fd can meaningfully block in this emulator:
// stdio (wired straight to the host's os.Stdin/Stdout/Stderr, see
// internal/fds) and pipes (real host pipes, see file.go's pipeEnd).
// Both wrap a real host fd number, so those fds get forwarded to an
// actual host poll(2)/ppoll(2) syscall -- reusing the exact same
// "forward to the real host fd" trick ioctl.go already uses for
// TCGETS/TIOCGWINSZ. Every other fd (regular VFS files, synthetic
// /proc entries, directories) is backed by ordinary Go file I/O that
// never blocks in this emulator, so those are answered immediately:
// ready for whatever was asked, no host syscall needed. If a
// poll() call mixes both kinds, the immediately-ready guest fds mean
// the host wait (if any) is done with a zero timeout instead of the
// caller's real one -- correct poll semantics ("return as soon as
// something is ready") without needing real cross-goroutine
// select-over-anything machinery.
package syscalls

import (
	"encoding/binary"
	"syscall"
	"time"
	"unsafe"

	"golinux/internal/consts"
	"golinux/internal/errno"
	"golinux/internal/fds"
)

func init() {
	register(consts.SYS_poll, sysPoll)
	register(consts.SYS_ppoll, sysPpoll)
}

// pollfdSize is sizeof(struct pollfd) on linux/amd64: int fd (4) +
// short events (2) + short revents (2) = 8 bytes, no padding (the
// struct's alignment requirement is 4, and 8 is already a multiple
// of that).
const pollfdSize = 8

// rawPollFd mirrors the kernel's struct pollfd layout exactly, so a
// slice of these can be handed straight to a real host poll(2)/
// ppoll(2) syscall via unsafe.Pointer.
type rawPollFd struct {
	fd      int32
	events  int16
	revents int16
}

// hostFdForFile reports the real host fd number backing f, for the
// two fd kinds that can actually block: stdio (via the same
// hostStdioFd lookup ioctl.go uses) and pipes. Every other kind
// (VFSFile, StaticFile, DirHandle) returns ok=false -- they're
// answered immediately in doPoll instead of going to the host.
func hostFdForFile(f fds.File) (uintptr, bool) {
	if hostFd, ok := hostStdioFd(f.Name()); ok {
		return hostFd, true
	}
	if pe, ok := f.(*pipeEnd); ok {
		return pe.f.Fd(), true
	}
	return 0, false
}

// sysPoll is poll(struct pollfd *fds, nfds_t nfds, int timeout). The
// timeout arg is a 32-bit int at the ABI level; the guest's syscall
// wrapper already sign-extends it into the full 64-bit register
// (exactly like every other plain `int` syscall arg), so reading the
// register as int64 recovers -1 ("block forever") correctly with no
// extra truncation step.
func sysPoll(proc Proc, fdsPtr, nfds, timeout, _, _, _ uint64) (int64, error) {
	return doPoll(proc, fdsPtr, nfds, int64(timeout))
}

// sysPpoll is ppoll(fds, nfds, const struct timespec *tmo, sigset_t
// *sigmask, size_t sigsetsize). The signal mask is ignored (this
// emulator doesn't model blocking/unblocking signals around a
// syscall -- see signal.go's stubs for the same simplification
// elsewhere); the timespec is converted to whole milliseconds for
// doPoll, which loses sub-millisecond precision but keeps this a
// single shared implementation rather than two nearly-identical
// ones -- an acceptable trade for what's meant to be a minimal
// implementation.
func sysPpoll(proc Proc, fdsPtr, nfds, tsPtr, _sigmaskPtr, _sigsetsize, _ uint64) (int64, error) {
	timeoutMs := int64(-1)
	if tsPtr != 0 {
		buf, err := proc.MemRead(tsPtr, 16)
		if err != nil {
			return int64(-errno.EFAULT), nil
		}
		sec := int64(binary.LittleEndian.Uint64(buf[0:8]))
		nsec := int64(binary.LittleEndian.Uint64(buf[8:16]))
		timeoutMs = sec*1000 + nsec/1_000_000
		if timeoutMs < 0 {
			timeoutMs = 0
		}
	}
	return doPoll(proc, fdsPtr, nfds, timeoutMs)
}

// doPoll is the shared implementation behind poll/ppoll. timeoutMs is
// -1 for "block forever", 0 for "return immediately", or a positive
// millisecond count.
func doPoll(proc Proc, fdsPtr uint64, nfds uint64, timeoutMs int64) (int64, error) {
	if nfds == 0 {
		// poll(NULL, 0, timeout) is a common portable-sleep idiom.
		// Honor it for real -- this only blocks the calling guest
		// process's own goroutine (see this file's doc comment), the
		// same way a real blocking poll() would only block the
		// calling thread.
		switch {
		case timeoutMs > 0:
			time.Sleep(time.Duration(timeoutMs) * time.Millisecond)
		case timeoutMs < 0:
			select {} // block forever, matching poll(NULL, 0, -1)
		}
		return 0, nil
	}

	raw, err := proc.MemRead(fdsPtr, int(nfds)*pollfdSize)
	if err != nil {
		return int64(-errno.EFAULT), nil
	}

	revents := make([]int16, nfds)
	var hostPollFds []rawPollFd
	var hostIdx []int
	immediateReady := false

	for i := 0; i < int(nfds); i++ {
		off := i * pollfdSize
		fd := int32(binary.LittleEndian.Uint32(raw[off : off+4]))
		events := int16(binary.LittleEndian.Uint16(raw[off+4 : off+6]))

		if fd < 0 {
			// POSIX: negative fd entries are ignored entirely and
			// always report revents == 0, never contributing to the
			// ready count.
			continue
		}

		f := proc.Fds().Get(int(fd))
		if f == nil {
			revents[i] = consts.POLLNVAL
			immediateReady = true
			continue
		}

		if hfd, ok := hostFdForFile(f); ok {
			hostPollFds = append(hostPollFds, rawPollFd{fd: int32(hfd), events: events})
			hostIdx = append(hostIdx, i)
			continue
		}

		// Regular VFS/static/procfs/directory fds are backed by
		// ordinary (non-blocking-in-practice) Go file I/O in this
		// emulator, so they're always ready for whatever was asked.
		var r int16
		if events&consts.POLLIN != 0 {
			r |= consts.POLLIN
		}
		if events&consts.POLLOUT != 0 {
			r |= consts.POLLOUT
		}
		revents[i] = r
		if r != 0 {
			immediateReady = true
		}
	}

	if len(hostPollFds) > 0 {
		waitMs := timeoutMs
		if immediateReady {
			waitMs = 0 // something's already ready -- don't block further
		}
		_, _, errno1 := syscall.Syscall(syscall.SYS_POLL,
			uintptr(unsafe.Pointer(&hostPollFds[0])),
			uintptr(len(hostPollFds)),
			uintptr(waitMs),
		)
		if errno1 != 0 {
			return int64(-int(errno1)), nil
		}
		for j, idx := range hostIdx {
			revents[idx] = hostPollFds[j].revents
		}
	}

	out := make([]byte, len(raw))
	copy(out, raw) // preserve each entry's fd/events fields verbatim
	var ready int64
	for i := 0; i < int(nfds); i++ {
		off := i*pollfdSize + 6
		binary.LittleEndian.PutUint16(out[off:off+2], uint16(revents[i]))
		if revents[i] != 0 {
			ready++
		}
	}
	if err := proc.MemWrite(fdsPtr, out); err != nil {
		return int64(-errno.EFAULT), nil
	}
	return ready, nil
}
