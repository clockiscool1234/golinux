package syscalls

import (
	"encoding/binary"

	"golinux/internal/consts"
	"golinux/internal/errno"
	"golinux/internal/procfs"
	"golinux/internal/vfs"
)

func init() {
	register(consts.SYS_stat, sysStat)
	register(consts.SYS_lstat, sysLstat)
	register(consts.SYS_fstat, sysFstat)
	register(consts.SYS_fstatat, sysFstatat)
	register(consts.SYS_access, sysAccess)
	register(consts.SYS_faccessat, sysFaccessat)
	register(consts.SYS_faccessat2, sysFaccessat)
	register(consts.SYS_chmod, sysChmod)
	register(consts.SYS_chown, sysChown)
	register(consts.SYS_lchown, sysLchown)
	register(consts.SYS_fchown, sysFchown)
	register(consts.SYS_umask, sysUmask)
	register(consts.SYS_readlink, sysReadlink)
	register(consts.SYS_readlinkat, sysReadlinkat)
}

// packStat serializes struct stat (x86_64 glibc/musl layout), 144
// bytes, matching sysemu/syscalls.py's _pack_stat.
func packStat(st vfs.Stat) []byte {
	buf := make([]byte, 144)
	le := binary.LittleEndian
	le.PutUint64(buf[0:8], st.Dev)
	le.PutUint64(buf[8:16], st.Ino)
	le.PutUint64(buf[16:24], st.Nlink)
	le.PutUint32(buf[24:28], st.Mode)
	le.PutUint32(buf[28:32], st.Uid)
	le.PutUint32(buf[32:36], st.Gid)
	// buf[36:40] __pad0, already zero
	le.PutUint64(buf[40:48], st.Rdev)
	le.PutUint64(buf[48:56], uint64(st.Size))
	le.PutUint64(buf[56:64], 512) // st_blksize
	le.PutUint64(buf[64:72], uint64((st.Size+511)/512))
	le.PutUint64(buf[72:80], uint64(st.Atime))
	le.PutUint64(buf[88:96], uint64(st.Mtime))
	le.PutUint64(buf[104:112], uint64(st.Ctime))
	return buf
}

func doStat(proc Proc, path string, buf uint64, follow bool) (int64, error) {
	p := path
	if follow {
		p = followSymlinks(proc, path)
	}
	if rel, ok := procRel(proc, p); ok {
		st, ok := procfs.Stat(rel, proc)
		if !ok {
			return int64(-errno.ENOENT), nil
		}
		if err := proc.MemWrite(buf, packStat(st)); err != nil {
			return int64(-errno.EFAULT), nil
		}
		return 0, nil
	}
	st, err := proc.VFS().Stat(p)
	if err != nil {
		return int64(-vfsErrno(err)), nil
	}
	if err := proc.MemWrite(buf, packStat(st)); err != nil {
		return int64(-errno.EFAULT), nil
	}
	return 0, nil
}

func sysStat(proc Proc, pathPtr, buf, _, _, _, _ uint64) (int64, error) {
	path, ok := cstr(proc, pathPtr, 4096)
	if !ok {
		return int64(-errno.EFAULT), nil
	}
	return doStat(proc, path, buf, true)
}

func sysLstat(proc Proc, pathPtr, buf, _, _, _, _ uint64) (int64, error) {
	path, ok := cstr(proc, pathPtr, 4096)
	if !ok {
		return int64(-errno.EFAULT), nil
	}
	return doStat(proc, path, buf, false) // symlinks not followed, by design
}

func sysFstat(proc Proc, fdNum, buf, _, _, _, _ uint64) (int64, error) {
	f := proc.Fds().Get(int(fdNum))
	if f == nil {
		return int64(-errno.EBADF), nil
	}
	guestPath := f.GuestPath()
	if guestPath == "" {
		// stdio / pipe: fabricate a minimal char-device stat.
		st := vfs.Stat{Mode: consts.S_IFCHR | 0o620, Nlink: 1}
		if err := proc.MemWrite(buf, packStat(st)); err != nil {
			return int64(-errno.EFAULT), nil
		}
		return 0, nil
	}
	return doStat(proc, guestPath, buf, true)
}

func sysFstatat(proc Proc, dirfd, pathPtr, buf, flags, _, _ uint64) (int64, error) {
	path, ok := cstr(proc, pathPtr, 4096)
	if !ok {
		return int64(-errno.EFAULT), nil
	}
	full, errn := resolve(proc, int32(dirfd), path)
	if errn != 0 {
		return int64(-errn), nil
	}
	follow := flags&consts.AT_SYMLINK_NOFOLLOW == 0
	return doStat(proc, full, buf, follow)
}

func sysAccess(proc Proc, pathPtr, _, _, _, _, _ uint64) (int64, error) {
	path, ok := cstr(proc, pathPtr, 4096)
	if !ok {
		return int64(-errno.EFAULT), nil
	}
	full := followSymlinks(proc, path)
	if rel, isProc := procRel(proc, full); isProc {
		if !procfs.Exists(rel, proc) {
			return int64(-errno.ENOENT), nil
		}
		return 0, nil
	}
	if !proc.VFS().Exists(full) {
		return int64(-errno.ENOENT), nil
	}
	return 0, nil
}

func sysFaccessat(proc Proc, dirfd, pathPtr, _, _, _, _ uint64) (int64, error) {
	path, ok := cstr(proc, pathPtr, 4096)
	if !ok {
		return int64(-errno.EFAULT), nil
	}
	full, errn := resolve(proc, int32(dirfd), path)
	if errn != 0 {
		return int64(-errn), nil
	}
	full = followSymlinks(proc, full)
	if rel, isProc := procRel(proc, full); isProc {
		if !procfs.Exists(rel, proc) {
			return int64(-errno.ENOENT), nil
		}
		return 0, nil
	}
	if !proc.VFS().Exists(full) {
		return int64(-errno.ENOENT), nil
	}
	return 0, nil
}

func sysChmod(proc Proc, pathPtr, mode, _, _, _, _ uint64) (int64, error) {
	path, ok := cstr(proc, pathPtr, 4096)
	if !ok {
		return int64(-errno.EFAULT), nil
	}
	path = followSymlinks(proc, path)
	if !proc.VFS().Exists(path) {
		return int64(-errno.ENOENT), nil
	}
	err := proc.VFS().SetMeta(path, func(m *vfs.Meta) { m.Mode = int(mode) & 0o7777 })
	if err != nil {
		return int64(-vfsErrno(err)), nil
	}
	return 0, nil
}

// chown/lchown/fchown are safely stubbed to succeed: this emulator
// doesn't enforce per-file uid/gid ownership checks beyond what's
// recorded in the vfs sidecar (see sysemu/syscalls.py's identical
// sys_fchownat comment), so there's nothing to actually change other
// than the bookkeeping value.
func sysChown(proc Proc, pathPtr, uid, gid, _, _, _ uint64) (int64, error) {
	path, ok := cstr(proc, pathPtr, 4096)
	if !ok {
		return int64(-errno.EFAULT), nil
	}
	path = followSymlinks(proc, path)
	if !proc.VFS().Exists(path) {
		return int64(-errno.ENOENT), nil
	}
	_ = proc.VFS().SetMeta(path, func(m *vfs.Meta) { m.Uid, m.Gid = int(uid), int(gid) })
	return 0, nil
}

func sysLchown(proc Proc, pathPtr, uid, gid, _, _, _ uint64) (int64, error) {
	path, ok := cstr(proc, pathPtr, 4096)
	if !ok {
		return int64(-errno.EFAULT), nil
	}
	if !proc.VFS().Exists(path) {
		return int64(-errno.ENOENT), nil
	}
	_ = proc.VFS().SetMeta(path, func(m *vfs.Meta) { m.Uid, m.Gid = int(uid), int(gid) })
	return 0, nil
}

func sysFchown(proc Proc, fdNum, uid, gid, _, _, _ uint64) (int64, error) {
	f := proc.Fds().Get(int(fdNum))
	if f == nil {
		return int64(-errno.EBADF), nil
	}
	if p := f.GuestPath(); p != "" {
		_ = proc.VFS().SetMeta(p, func(m *vfs.Meta) { m.Uid, m.Gid = int(uid), int(gid) })
	}
	return 0, nil
}

func sysUmask(proc Proc, mask, _, _, _, _, _ uint64) (int64, error) {
	return int64(proc.SetUmask(int(mask) & 0o777)), nil
}

func doReadlink(proc Proc, path string, buf uint64, bufsiz int) (int64, error) {
	var target string
	if rel, ok := procRel(proc, path); ok {
		t, ok := procfs.Readlink(rel, proc)
		if !ok {
			return int64(-errno.EINVAL), nil
		}
		target = t
	} else {
		t, err := proc.VFS().Readlink(path)
		if err != nil {
			return int64(-vfsErrno(err)), nil
		}
		target = t
	}
	data := []byte(target)
	if len(data) > bufsiz {
		data = data[:bufsiz]
	}
	if err := proc.MemWrite(buf, data); err != nil {
		return int64(-errno.EFAULT), nil
	}
	return int64(len(data)), nil
}

func sysReadlink(proc Proc, pathPtr, buf, bufsiz, _, _, _ uint64) (int64, error) {
	path, ok := cstr(proc, pathPtr, 4096)
	if !ok {
		return int64(-errno.EFAULT), nil
	}
	return doReadlink(proc, path, buf, int(bufsiz))
}

func sysReadlinkat(proc Proc, dirfd, pathPtr, buf, bufsiz, _, _ uint64) (int64, error) {
	path, ok := cstr(proc, pathPtr, 4096)
	if !ok {
		return int64(-errno.EFAULT), nil
	}
	full, errn := resolve(proc, int32(dirfd), path)
	if errn != 0 {
		return int64(-errn), nil
	}
	return doReadlink(proc, full, buf, int(bufsiz))
}
