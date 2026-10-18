// select.go implements select(2) and pselect6(2) on top of the same
// host-poll plumbing poll.go built (see that file's package doc
// comment for why a real, blocking host wait is safe here: each guest
// process runs on its own goroutine). The fd_set wire format is the
// only new part: three 1024-bit bitmaps (read/write/except, 128 bytes
// each) plus, for pselect6, a timespec and a sigset this emulator
// ignores (see signal.go's stubs for the same simplification).
//
// Why this finally exists: musl's stdio calls select() (not poll())
// before a blocking read when the caller asked for a timeout, and
// apk's fetch progress loop sits in exactly that shape -- select()
// returned ENOSYS and the loop retried forever, hanging `apk update`
// mid-download even though the underlying HTTP fetch had finished.
//
// Semantics: the kernel's select blocks until one of the watched fds
// is ready or the timeout expires. Only stdio, pipes, and sockets
// (the fd kinds with real host fds, exactly as in hostFdForFile) can
// block; every other kind is always immediately ready, so a mixed
// call degrades to a zero-timeout host poll over the real fds, the
// same compromise poll.go's doPoll makes. select() with nfds beyond
// the three bitmaps' 1024-fd capacity returns EINVAL, matching the
// real kernel.

package syscalls

import (
	"encoding/binary"
	"time"

	"golinux/internal/consts"
	"golinux/internal/errno"
	"golinux/internal/fds"
)

func init() {
	register(consts.SYS_select, sysSelect)
	register(consts.SYS_pselect6, sysPselect6)
}

// fdSetBytes is sizeof(fd_set) on linux: 1024 bits / 8.
const fdSetBytes = 128

// fdSetIsSet reports whether bit fd is set in a 128-byte fd_set.
func fdSetIsSet(set []byte, fd int) bool {
	if fd < 0 || fd >= fdSetBytes*8 {
		return false
	}
	return set[fd/8]&(1<<(fd%8)) != 0
}

// fdSetSet sets bit fd in a 128-byte fd_set.
func fdSetSet(set []byte, fd int) {
	if fd >= 0 && fd < fdSetBytes*8 {
		set[fd/8] |= 1 << (fd % 8)
	}
}

// sysSelect is select(nfds, readfds, writefds, exceptfds, timeout).
// The timeout pointer points at a struct timeval (8 bytes: seconds +
// microseconds); NULL means "block forever". On return the kernel
// rewrites the fd_sets in place to hold only the ready fds, and the
// timeval to hold the time remaining (Linux behavior; this reports
// the remaining time honestly since the host poll gives it to us).
func sysSelect(proc Proc, nfds, readPtr, writePtr, exceptPtr, timeoutPtr, _ uint64) (int64, error) {
	var timeoutMs int64 = -1
	haveTimeout := false
	if timeoutPtr != 0 {
		tv, err := proc.MemRead(timeoutPtr, 16)
		if err != nil {
			return int64(-errno.EFAULT), nil
		}
		sec := int64(binary.LittleEndian.Uint64(tv[0:8]))
		usec := int64(binary.LittleEndian.Uint64(tv[8:16]))
		timeoutMs = sec*1000 + usec/1000
		haveTimeout = true
	}
	n, leftMs, err := doSelect(proc, int(nfds), readPtr, writePtr, exceptPtr, timeoutMs)
	if err != 0 {
		return int64(-err), nil
	}
	if haveTimeout && timeoutPtr != 0 {
		// Linux rewrites the timeval with the time left; the real
		// kernel also rounds down to the tick, but reporting the
		// honest remainder is strictly closer than zeroing it.
		sec := leftMs / 1000
		usec := (leftMs % 1000) * 1000
		if leftMs < 0 {
			sec, usec = 0, 0
		}
		tv := make([]byte, 16)
		binary.LittleEndian.PutUint64(tv[0:8], uint64(sec))
		binary.LittleEndian.PutUint64(tv[8:16], uint64(usec))
		if werr := proc.MemWrite(timeoutPtr, tv); werr != nil {
			return int64(-errno.EFAULT), nil
		}
	}
	return n, nil
}

// sysPselect6 is pselect6(nfds, readfds, writefds, exceptfds,
// timespec, sigmask-ptr-struct). The sigmask is ignored (see the
// package doc comment); the timespec carries nanoseconds.
func sysPselect6(proc Proc, nfds, readPtr, writePtr, exceptPtr, tsPtr, _sigmaskPtr uint64) (int64, error) {
	var timeoutMs int64 = -1
	if tsPtr != 0 {
		ts, err := proc.MemRead(tsPtr, 16)
		if err != nil {
			return int64(-errno.EFAULT), nil
		}
		sec := int64(binary.LittleEndian.Uint64(ts[0:8]))
		nsec := int64(binary.LittleEndian.Uint64(ts[8:16]))
		timeoutMs = sec*1000 + nsec/1_000_000
		if timeoutMs < 0 {
			timeoutMs = 0
		}
	}
	n, _, errn := doSelect(proc, int(nfds), readPtr, writePtr, exceptPtr, timeoutMs)
	if errn != 0 {
		return int64(-errn), nil
	}
	return n, nil
}

// doSelect is the shared select/pselect6 core. Returns (ready count,
// milliseconds remaining, errno). timeoutMs is -1 for "block
// forever".
func doSelect(proc Proc, nfds int, readPtr, writePtr, exceptPtr uint64, timeoutMs int64) (int64, int64, int) {
	if nfds < 0 || nfds > fdSetBytes*8 {
		return 0, 0, errno.EINVAL
	}

	var readSet, writeSet, exceptSet []byte
	if readPtr != 0 {
		b, err := proc.MemRead(readPtr, fdSetBytes)
		if err != nil {
			return 0, 0, errno.EFAULT
		}
		readSet = b
	}
	if writePtr != 0 {
		b, err := proc.MemRead(writePtr, fdSetBytes)
		if err != nil {
			return 0, 0, errno.EFAULT
		}
		writeSet = b
	}
	if exceptPtr != 0 {
		// The exceptfds set is read for API compliance (fds watched
		// for exceptions) but nothing this emulator models -- no
		// out-of-band data, no urgent TCP conditions -- can fire it,
		// so it's zeroed on return below like a real kernel that
		// simply never sees an exception on these fds.
		b, err := proc.MemRead(exceptPtr, fdSetBytes)
		if err != nil {
			return 0, 0, errno.EFAULT
		}
		exceptSet = b
		_ = exceptSet
	}

	// Build the host poll list: one entry per watched (fd, direction).
	var pfds []rawPollFd
	var guestIdx []int    // pfds[i] watches which guest fd
	var watchWrite []bool // ...for write-readiness (true) or read (false)
	for fd := 0; fd < nfds; fd++ {
		inRead := readSet != nil && fdSetIsSet(readSet, fd)
		inWrite := writeSet != nil && fdSetIsSet(writeSet, fd)
		if !inRead && !inWrite {
			continue
		}
		f := proc.Fds().Get(fd)
		if f == nil {
			continue
		}
		hostFd, hasHostFd := hostFdForFile(f)
		if !hasHostFd {
			continue // always-ready kinds are handled after the host wait
		}
		if inRead && inWrite {
			// poll both directions needs two entries; watch read
			// first, write second.
			pfds = append(pfds, rawPollFd{fd: int32(hostFd), events: pollIn | pollErr})
			guestIdx = append(guestIdx, fd)
			watchWrite = append(watchWrite, false)
			pfds = append(pfds, rawPollFd{fd: int32(hostFd), events: pollOut | pollErr})
			guestIdx = append(guestIdx, fd)
			watchWrite = append(watchWrite, true)
		} else if inRead {
			pfds = append(pfds, rawPollFd{fd: int32(hostFd), events: pollIn | pollErr})
			guestIdx = append(guestIdx, fd)
			watchWrite = append(watchWrite, false)
		} else {
			pfds = append(pfds, rawPollFd{fd: int32(hostFd), events: pollOut | pollErr})
			guestIdx = append(guestIdx, fd)
			watchWrite = append(watchWrite, true)
		}
	}

	start := time.Now()
	ready := int64(0)
	outRead := make([]byte, fdSetBytes)
	outWrite := make([]byte, fdSetBytes)
	outExcept := make([]byte, fdSetBytes)
	var readyGuest map[int]bool

	// Always-ready fds (regular files etc.) count immediately and
	// force the host wait to be non-blocking.
	waitMs := timeoutMs
	for fd := 0; fd < nfds; fd++ {
		inRead := readSet != nil && fdSetIsSet(readSet, fd)
		inWrite := writeSet != nil && fdSetIsSet(writeSet, fd)
		if !inRead && !inWrite {
			continue
		}
		f := proc.Fds().Get(fd)
		if f == nil {
			continue
		}
		hostFd, hasHostFd := hostFdForFile(f)
		if !hasHostFd && isAlwaysReadyFile(f) {
			if inRead {
				fdSetSet(outRead, fd)
			}
			if inWrite {
				fdSetSet(outWrite, fd)
			}
			ready++
			if waitMs < 0 || waitMs > 0 {
				waitMs = 0
			}
		}
		_ = hostFd
	}

	if len(pfds) > 0 {
		// Reuse doPoll's rawPollFd wait: if always-ready fds forced a
		// zero wait, don't block on the host at all.
		wait := waitMs
		if wait < 0 {
			wait = 0
		}
		if ready > 0 {
			wait = 0
		}
		_ = hostPoll(pfds, wait)
		readyGuest = map[int]bool{}
		for i, p := range pfds {
			if p.revents == 0 {
				continue
			}
			fd := guestIdx[i]
			if readyGuest[fd] {
				continue
			}
			readable := !watchWrite[i] && p.revents&(pollIn|pollErr|pollHup) != 0
			writable := watchWrite[i] && p.revents&(pollOut|pollErr) != 0
			if readable || writable {
				if readable {
					fdSetSet(outRead, fd)
				}
				if writable {
					fdSetSet(outWrite, fd)
				}
				readyGuest[fd] = true
				ready++
			}
		}
	}

	// Time remaining: for an always-ready return, keep the caller's
	// original budget; else count down from the start.
	left := timeoutMs
	if timeoutMs >= 0 {
		elapsed := time.Since(start).Milliseconds()
		left = timeoutMs - elapsed
		if left < 0 {
			left = 0
		}
	}

	if readPtr != 0 {
		if err := proc.MemWrite(readPtr, outRead); err != nil {
			return 0, 0, errno.EFAULT
		}
	}
	if writePtr != 0 {
		if err := proc.MemWrite(writePtr, outWrite); err != nil {
			return 0, 0, errno.EFAULT
		}
	}
	if exceptPtr != 0 {
		if err := proc.MemWrite(exceptPtr, outExcept); err != nil {
			return 0, 0, errno.EFAULT
		}
	}
	return ready, left, 0
}

// pollIn/pollOut/pollErr/pollHup are the poll(2) event bits select
// maps onto (POLLIN=1, POLLOUT=4, POLLERR=8, POLLHUP=16 on Linux).
const (
	pollIn  = 1
	pollOut = 4
	pollErr = 8
	pollHup = 16
)

// isAlwaysReadyFile reports whether f is a kind that never blocks in
// this emulator (VFS files, procfs entries, directories) -- the same
// set poll.go's doPoll answers immediately.
func isAlwaysReadyFile(f interface{}) bool {
	switch f.(type) {
	case *fds.VFSFile, *fds.StaticFile, *fds.DirHandle:
		return true
	}
	return false
}
