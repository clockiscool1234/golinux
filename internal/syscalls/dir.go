package syscalls

import (
	"encoding/binary"
	"strings"

	"golinux/internal/consts"
	"golinux/internal/errno"
	"golinux/internal/fds"
)

func init() {
	register(consts.SYS_getcwd, sysGetcwd)
	register(consts.SYS_chdir, sysChdir)
	register(consts.SYS_mkdir, sysMkdir)
	register(consts.SYS_mkdirat, sysMkdirat)
	register(consts.SYS_rmdir, sysRmdir)
	register(consts.SYS_unlink, sysUnlink)
	register(consts.SYS_unlinkat, sysUnlinkat)
	register(consts.SYS_rename, sysRename)
	register(consts.SYS_renameat, sysRenameat)
	register(consts.SYS_symlink, sysSymlink)
	register(consts.SYS_link, sysLink)
	register(consts.SYS_linkat, sysLinkat)
	register(consts.SYS_getdents64, sysGetdents64)
}

// --------------------------------------------------------------------------
// cwd
// --------------------------------------------------------------------------

func sysGetcwd(proc Proc, buf, size, _, _, _, _ uint64) (int64, error) {
	data := append([]byte(proc.Cwd()), 0)
	if uint64(len(data)) > size {
		return int64(-errno.ERANGE), nil
	}
	if err := proc.MemWrite(buf, data); err != nil {
		return int64(-errno.EFAULT), nil
	}
	return int64(len(data)), nil
}

func sysChdir(proc Proc, pathPtr, _, _, _, _, _ uint64) (int64, error) {
	path, ok := cstr(proc, pathPtr, 4096)
	if !ok {
		return int64(-errno.EFAULT), nil
	}
	full := path
	if !strings.HasPrefix(path, "/") {
		full = strings.TrimRight(proc.Cwd(), "/") + "/" + path
	}
	if !proc.VFS().IsDir(full) {
		return int64(-errno.ENOTDIR), nil
	}
	proc.SetCwd(full)
	return 0, nil
}

// --------------------------------------------------------------------------
// mkdir / rmdir / unlink
// --------------------------------------------------------------------------

func sysMkdir(proc Proc, pathPtr, mode, _, _, _, _ uint64) (int64, error) {
	path, ok := cstr(proc, pathPtr, 4096)
	if !ok {
		return int64(-errno.EFAULT), nil
	}
	m := int(mode) & 0o777
	if m == 0 {
		m = 0o755
	}
	if err := proc.VFS().Mkdir(resolveAbs(proc, path), m); err != nil {
		return int64(-vfsErrno(err)), nil
	}
	return 0, nil
}

func sysMkdirat(proc Proc, dirfd, pathPtr, mode, _, _, _ uint64) (int64, error) {
	path, ok := cstr(proc, pathPtr, 4096)
	if !ok {
		return int64(-errno.EFAULT), nil
	}
	full, errn := resolve(proc, int32(dirfd), path)
	if errn != 0 {
		return int64(-errn), nil
	}
	m := int(mode) & 0o777
	if m == 0 {
		m = 0o755
	}
	if err := proc.VFS().Mkdir(full, m); err != nil {
		return int64(-vfsErrno(err)), nil
	}
	return 0, nil
}

func sysRmdir(proc Proc, pathPtr, _, _, _, _, _ uint64) (int64, error) {
	path, ok := cstr(proc, pathPtr, 4096)
	if !ok {
		return int64(-errno.EFAULT), nil
	}
	if err := proc.VFS().Rmdir(resolveAbs(proc, path)); err != nil {
		return int64(-vfsErrno(err)), nil
	}
	return 0, nil
}

func sysUnlink(proc Proc, pathPtr, _, _, _, _, _ uint64) (int64, error) {
	path, ok := cstr(proc, pathPtr, 4096)
	if !ok {
		return int64(-errno.EFAULT), nil
	}
	if err := proc.VFS().Unlink(resolveAbs(proc, path)); err != nil {
		return int64(-vfsErrno(err)), nil
	}
	return 0, nil
}

const atRemoveDir = 0x200

func sysUnlinkat(proc Proc, dirfd, pathPtr, flags, _, _, _ uint64) (int64, error) {
	path, ok := cstr(proc, pathPtr, 4096)
	if !ok {
		return int64(-errno.EFAULT), nil
	}
	full, errn := resolve(proc, int32(dirfd), path)
	if errn != 0 {
		return int64(-errn), nil
	}
	var err error
	if flags&atRemoveDir != 0 {
		err = proc.VFS().Rmdir(full)
	} else {
		err = proc.VFS().Unlink(full)
	}
	if err != nil {
		return int64(-vfsErrno(err)), nil
	}
	return 0, nil
}

// --------------------------------------------------------------------------
// rename
// --------------------------------------------------------------------------

func sysRename(proc Proc, oldPtr, newPtr, _, _, _, _ uint64) (int64, error) {
	oldPath, ok1 := cstr(proc, oldPtr, 4096)
	newPath, ok2 := cstr(proc, newPtr, 4096)
	if !ok1 || !ok2 {
		return int64(-errno.EFAULT), nil
	}
	if err := proc.VFS().Rename(oldPath, newPath); err != nil {
		return int64(-vfsErrno(err)), nil
	}
	return 0, nil
}

func sysRenameat(proc Proc, olddirfd, oldPtr, newdirfd, newPtr, _, _ uint64) (int64, error) {
	oldRaw, ok1 := cstr(proc, oldPtr, 4096)
	newRaw, ok2 := cstr(proc, newPtr, 4096)
	if !ok1 || !ok2 {
		return int64(-errno.EFAULT), nil
	}
	oldPath, errn := resolve(proc, int32(olddirfd), oldRaw)
	if errn != 0 {
		return int64(-errn), nil
	}
	newPath, errn := resolve(proc, int32(newdirfd), newRaw)
	if errn != 0 {
		return int64(-errn), nil
	}
	if err := proc.VFS().Rename(oldPath, newPath); err != nil {
		return int64(-vfsErrno(err)), nil
	}
	return 0, nil
}

// --------------------------------------------------------------------------
// symlink / link
// --------------------------------------------------------------------------

func sysSymlink(proc Proc, targetPtr, linkpathPtr, _, _, _, _ uint64) (int64, error) {
	target, ok1 := cstr(proc, targetPtr, 4096)
	linkpath, ok2 := cstr(proc, linkpathPtr, 4096)
	if !ok1 || !ok2 {
		return int64(-errno.EFAULT), nil
	}
	full := linkpath
	if !strings.HasPrefix(linkpath, "/") {
		full = strings.TrimRight(proc.Cwd(), "/") + "/" + linkpath
	}
	if proc.VFS().Exists(full) {
		return int64(-errno.EEXIST), nil
	}
	if err := proc.VFS().Symlink(target, full); err != nil {
		return int64(-vfsErrno(err)), nil
	}
	return 0, nil
}

func sysLink(proc Proc, oldPtr, newPtr, _, _, _, _ uint64) (int64, error) {
	oldRaw, ok1 := cstr(proc, oldPtr, 4096)
	newRaw, ok2 := cstr(proc, newPtr, 4096)
	if !ok1 || !ok2 {
		return int64(-errno.EFAULT), nil
	}
	oldFull := oldRaw
	if !strings.HasPrefix(oldRaw, "/") {
		oldFull = strings.TrimRight(proc.Cwd(), "/") + "/" + oldRaw
	}
	newFull := newRaw
	if !strings.HasPrefix(newRaw, "/") {
		newFull = strings.TrimRight(proc.Cwd(), "/") + "/" + newRaw
	}
	if err := proc.VFS().Link(oldFull, newFull); err != nil {
		return int64(-vfsErrno(err)), nil
	}
	return 0, nil
}

func sysLinkat(proc Proc, olddirfd, oldpathPtr, newdirfd, newpathPtr, _, _ uint64) (int64, error) {
	oldRaw, ok1 := cstr(proc, oldpathPtr, 4096)
	newRaw, ok2 := cstr(proc, newpathPtr, 4096)
	if !ok1 || !ok2 {
		return int64(-errno.EFAULT), nil
	}
	// The AT_EMPTY_PATH / O_TMPFILE linkat() pattern apk uses isn't
	// supported yet (O_TMPFILE itself isn't ported -- see file.go's
	// openCommon), only the ordinary two-path form.
	oldFull, errn := resolve(proc, int32(olddirfd), oldRaw)
	if errn != 0 {
		return int64(-errn), nil
	}
	newFull, errn := resolve(proc, int32(newdirfd), newRaw)
	if errn != 0 {
		return int64(-errn), nil
	}
	if err := proc.VFS().Link(oldFull, newFull); err != nil {
		return int64(-vfsErrno(err)), nil
	}
	return 0, nil
}

// --------------------------------------------------------------------------
// getdents64
// --------------------------------------------------------------------------

func sysGetdents64(proc Proc, fdNum, buf, count, _, _, _ uint64) (int64, error) {
	f := proc.Fds().Get(int(fdNum))
	if f == nil || !f.IsDir() {
		return int64(-errno.ENOTDIR), nil
	}
	dh, ok := f.(*fds.DirHandle)
	if !ok {
		return int64(-errno.ENOTDIR), nil
	}
	names := dh.Entries()
	var out []byte
	for dh.Pos < len(names) {
		name := names[dh.Pos]
		recName := append([]byte(name), 0)
		reclen := (19 + len(recName) + 7) / 8 * 8
		if len(out)+reclen > int(count) {
			break
		}
		rec := make([]byte, reclen)
		binary.LittleEndian.PutUint64(rec[0:8], 1)                 // d_ino
		binary.LittleEndian.PutUint64(rec[8:16], uint64(dh.Pos+1)) // d_off
		binary.LittleEndian.PutUint16(rec[16:18], uint16(reclen))  // d_reclen
		rec[18] = 0                                                // d_type = DT_UNKNOWN
		copy(rec[19:], recName)
		out = append(out, rec...)
		dh.Pos++
	}
	if err := proc.MemWrite(buf, out); err != nil {
		return int64(-errno.EFAULT), nil
	}
	return int64(len(out)), nil
}
