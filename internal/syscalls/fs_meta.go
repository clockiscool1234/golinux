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
	register(consts.SYS_fchownat, sysFchownat)
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
	p := resolveAbs(proc, path)
	if follow {
		p = followSymlinks(proc, p)
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
		// stdio / pipe / socket: fabricate a minimal stat. Sockets
		// report S_IFSOCK (musl's isatty-adjacent helpers and
		// connect()-preflight both fstat(2) the fd and branch on the
		// file type); everything else here is a char device.
		st := vfs.Stat{Mode: consts.S_IFCHR | 0o620, Nlink: 1}
		if _, isSock := f.(*GuestSocket); isSock {
			st.Mode = consts.S_IFSOCK | 0o777
		}
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
	full := followSymlinks(proc, resolveAbs(proc, path))
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
	path = followSymlinks(proc, resolveAbs(proc, path))
	if !proc.VFS().Exists(path) {
		return int64(-errno.ENOENT), nil
	}
	err := proc.VFS().SetMeta(path, func(m *vfs.Meta) { m.Mode = int(mode) & 0o7777 })
	if err != nil {
		return int64(-vfsErrno(err)), nil
	}
	return 0, nil
}

func sysChown(proc Proc, pathPtr, uid, gid, _, _, _ uint64) (int64, error) {
	path, ok := cstr(proc, pathPtr, 4096)
	if !ok {
		return int64(-errno.EFAULT), nil
	}
	path = followSymlinks(proc, resolveAbs(proc, path))
	return chownPath(proc, path, uid, gid), nil
}

func sysLchown(proc Proc, pathPtr, uid, gid, _, _, _ uint64) (int64, error) {
	path, ok := cstr(proc, pathPtr, 4096)
	if !ok {
		return int64(-errno.EFAULT), nil
	}
	return chownPath(proc, resolveAbs(proc, path), uid, gid), nil
}

func sysFchown(proc Proc, fdNum, uid, gid, _, _, _ uint64) (int64, error) {
	f := proc.Fds().Get(int(fdNum))
	if f == nil {
		return int64(-errno.EBADF), nil
	}
	if p := f.GuestPath(); p != "" {
		return chownPath(proc, p, uid, gid), nil
	}
	return 0, nil
}

func sysFchownat(proc Proc, dirfd, pathPtr, uid, gid, flags, _ uint64) (int64, error) {
	path, ok := cstr(proc, pathPtr, 4096)
	if !ok {
		return int64(-errno.EFAULT), nil
	}
	allowed := uint64(consts.AT_SYMLINK_NOFOLLOW | consts.AT_EMPTY_PATH)
	if flags&^allowed != 0 {
		return int64(-errno.EINVAL), nil
	}
	if path == "" && flags&consts.AT_EMPTY_PATH == 0 {
		return int64(-errno.ENOENT), nil
	}
	if path == "" && flags&consts.AT_EMPTY_PATH != 0 {
		if int32(dirfd) == consts.AT_FDCWD {
			path = proc.Cwd()
		} else {
			f := proc.Fds().Get(int(int32(dirfd)))
			if f == nil || f.GuestPath() == "" {
				return int64(-errno.EBADF), nil
			}
			path = f.GuestPath()
		}
	} else {
		var errn int
		path, errn = resolve(proc, int32(dirfd), path)
		if errn != 0 {
			return int64(-errn), nil
		}
	}
	if flags&consts.AT_SYMLINK_NOFOLLOW == 0 {
		path = followSymlinks(proc, path)
	}
	return chownPath(proc, path, uid, gid), nil
}

func chownPath(proc Proc, path string, uid, gid uint64) int64 {
	if !proc.VFS().Exists(path) {
		return int64(-errno.ENOENT)
	}
	err := proc.VFS().SetMeta(path, func(m *vfs.Meta) {
		if uint32(uid) != ^uint32(0) {
			m.Uid = int(uint32(uid))
		}
		if uint32(gid) != ^uint32(0) {
			m.Gid = int(uint32(gid))
		}
	})
	if err != nil {
		return int64(-vfsErrno(err))
	}
	return 0
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
	return doReadlink(proc, resolveAbs(proc, path), buf, int(bufsiz))
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
