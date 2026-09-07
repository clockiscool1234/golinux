// misc.go: a grab-bag of smaller syscalls that don't earn their own
// file yet. select/pselect6 are intentionally NOT here -- they need
// the same host-fd-aware plumbing poll.go added for poll/ppoll, just
// for a different wire format (fd_set bitmasks rather than a pollfd
// array); left for a follow-up pass since nothing exercised so far
// needs them. Calling them ENOSYS is safer than a fake "nothing is
// ever ready" or "everything is always ready" stub, either of which
// would make callers spin or hang in confusing ways.
package syscalls

import (
	"encoding/binary"

	"golinux/internal/consts"
	"golinux/internal/errno"
	"golinux/internal/fds"
)

func init() {
	register(consts.SYS_getrlimit, sysGetrlimit)
	register(consts.SYS_prlimit64, sysPrlimit64)
	register(consts.SYS_statfs, sysStatfs)
	register(consts.SYS_sync, sysSync)
	register(consts.SYS_flock, sysFlock)
	register(consts.SYS_fsync, sysFsync)
	register(consts.SYS_ftruncate, sysFtruncate)
	register(consts.SYS_utimensat, sysUtimensat)
	register(consts.SYS_utimes, sysUtimes)
}

func writeRlimInfinity(proc Proc, addr uint64) error {
	buf := make([]byte, 16)
	binary.LittleEndian.PutUint64(buf[0:8], consts.RLIM_INFINITY)
	binary.LittleEndian.PutUint64(buf[8:16], consts.RLIM_INFINITY)
	return proc.MemWrite(addr, buf)
}

func sysGetrlimit(proc Proc, _resource, rlim, _, _, _, _ uint64) (int64, error) {
	if err := writeRlimInfinity(proc, rlim); err != nil {
		return int64(-errno.EFAULT), nil
	}
	return 0, nil
}

func sysPrlimit64(proc Proc, _pid, _resource, _newLimit, oldLimit, _, _ uint64) (int64, error) {
	if oldLimit != 0 {
		if err := writeRlimInfinity(proc, oldLimit); err != nil {
			return int64(-errno.EFAULT), nil
		}
	}
	return 0, nil
}

// sysStatfs reports a generous, fake 10GB-free filesystem (struct
// statfs, x86_64, 120 bytes) so callers that check available space
// before writing (e.g. package managers) don't abort prematurely.
func sysStatfs(proc Proc, _pathPtr, buf, _, _, _, _ uint64) (int64, error) {
	const bsize = 4096
	const blocks = 10 * 1024 * 1024 * 1024 / bsize // 10 GB total, all free
	out := make([]byte, 120)
	le := binary.LittleEndian
	le.PutUint64(out[0:8], 0xEF53)    // f_type (ext2/3/4 magic)
	le.PutUint64(out[8:16], bsize)    // f_bsize
	le.PutUint64(out[16:24], blocks)  // f_blocks
	le.PutUint64(out[24:32], blocks)  // f_bfree
	le.PutUint64(out[32:40], blocks)  // f_bavail
	le.PutUint64(out[40:48], 1000000) // f_files
	le.PutUint64(out[48:56], 1000000) // f_ffree
	le.PutUint64(out[64:72], 255)     // f_namelen (f_fsid occupies 56:64, left 0)
	if err := proc.MemWrite(buf, out); err != nil {
		return int64(-errno.EFAULT), nil
	}
	return 0, nil
}

func sysSync(proc Proc, _, _, _, _, _, _ uint64) (int64, error)  { return 0, nil }
func sysFlock(proc Proc, _, _, _, _, _, _ uint64) (int64, error) { return 0, nil }
func sysFsync(proc Proc, _, _, _, _, _, _ uint64) (int64, error) { return 0, nil }

func sysFtruncate(proc Proc, fdNum, length, _, _, _, _ uint64) (int64, error) {
	f := proc.Fds().Get(int(fdNum))
	if f == nil {
		return int64(-errno.EBADF), nil
	}
	vf, ok := f.(*fds.VFSFile)
	if !ok {
		return int64(-errno.EBADF), nil
	}
	if err := vf.Truncate(int64(length)); err != nil {
		return int64(-errno.EIO), nil
	}
	return 0, nil
}

func sysUtimensat(proc Proc, dirfd, pathPtr, _timesPtr, flags, _, _ uint64) (int64, error) {
	if pathPtr == 0 {
		return 0, nil // operating on dirfd itself (futimens-style) -- always "fine"
	}
	path, ok := cstr(proc, pathPtr, 4096)
	if !ok {
		return int64(-errno.EFAULT), nil
	}
	full, errn := resolve(proc, int32(dirfd), path)
	if errn != 0 {
		return int64(-errn), nil
	}
	if flags&consts.AT_SYMLINK_NOFOLLOW == 0 {
		full = followSymlinks(proc, full)
	}
	if !proc.VFS().Exists(full) {
		return int64(-errno.ENOENT), nil
	}
	return 0, nil
}

func sysUtimes(proc Proc, pathPtr, _timesPtr, _, _, _, _ uint64) (int64, error) {
	if pathPtr == 0 {
		return int64(-errno.EFAULT), nil
	}
	path, ok := cstr(proc, pathPtr, 4096)
	if !ok {
		return int64(-errno.EFAULT), nil
	}
	full := resolveAbs(proc, path)
	if !proc.VFS().Exists(full) {
		return int64(-errno.ENOENT), nil
	}
	return 0, nil
}
