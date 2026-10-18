package syscalls

import (
	"os"

	"golinux/internal/consts"
	"golinux/internal/devices"
	"golinux/internal/errno"
	"golinux/internal/fds"
	"golinux/internal/procfs"
)

func init() {
	register(consts.SYS_read, sysRead)
	register(consts.SYS_write, sysWrite)
	register(consts.SYS_pread64, sysPread64)
	register(consts.SYS_pwrite64, sysPwrite64)
	register(consts.SYS_readv, sysReadv)
	register(consts.SYS_writev, sysWritev)
	register(consts.SYS_open, sysOpen)
	register(consts.SYS_openat, sysOpenat)
	register(consts.SYS_creat, sysCreat)
	register(consts.SYS_close, sysClose)
	register(consts.SYS_lseek, sysLseek)
	register(consts.SYS_dup, sysDup)
	register(consts.SYS_dup2, sysDup2)
	register(consts.SYS_fcntl, sysFcntl)
	register(consts.SYS_pipe, sysPipe)
	register(consts.SYS_pipe2, sysPipe2)
}

// --------------------------------------------------------------------------
// read / write
// --------------------------------------------------------------------------

func sysRead(proc Proc, fdNum, buf, count, _, _, _ uint64) (int64, error) {
	f := proc.Fds().Get(int(fdNum))
	if f == nil {
		return int64(-errno.EBADF), nil
	}
	if f.IsDir() {
		return int64(-errno.EISDIR), nil
	}
	data, err := f.Read(int(count))
	if err != nil {
		return int64(-readErrno(err)), nil
	}
	if err := proc.MemWrite(buf, data); err != nil {
		return int64(-errno.EFAULT), nil
	}
	return int64(len(data)), nil
}

func sysWrite(proc Proc, fdNum, buf, count, _, _, _ uint64) (int64, error) {
	f := proc.Fds().Get(int(fdNum))
	if f == nil {
		return int64(-errno.EBADF), nil
	}
	data, err := proc.MemRead(buf, int(count))
	if err != nil {
		return int64(-errno.EFAULT), nil
	}
	n, err := f.Write(data)
	if err != nil {
		return int64(-writeErrno(err)), nil
	}
	return int64(n), nil
}

// writeErrno extracts a specific errno from a *fds.ErrnoError (e.g.
// /dev/full reporting ENOSPC on every write, or a nonblocking socket
// reporting EAGAIN), falling back to EIO.
func writeErrno(err error) int {
	if ee, ok := err.(*fds.ErrnoError); ok {
		return ee.Errno
	}
	return errno.EIO
}

// readErrno is writeErrno's read-side twin. A plain nonblocking
// EAGAIN from a socket must reach the guest as -EAGAIN, not as a
// 0-byte read (which reads as EOF) or a generic EIO.
func readErrno(err error) int {
	if ee, ok := err.(*fds.ErrnoError); ok {
		return ee.Errno
	}
	return errno.EIO
}

func sysPread64(proc Proc, fdNum, buf, count, offset, _, _ uint64) (int64, error) {
	f := proc.Fds().Get(int(fdNum))
	if f == nil {
		return int64(-errno.EBADF), nil
	}
	vf, ok := f.(*fds.VFSFile)
	if !ok {
		return int64(-errno.ESPIPE), nil
	}
	data, err := vf.PreadAt(int(count), int64(offset))
	if err != nil {
		return int64(-errno.EIO), nil
	}
	if err := proc.MemWrite(buf, data); err != nil {
		return int64(-errno.EFAULT), nil
	}
	return int64(len(data)), nil
}

func sysPwrite64(proc Proc, fdNum, buf, count, offset, _, _ uint64) (int64, error) {
	f := proc.Fds().Get(int(fdNum))
	if f == nil {
		return int64(-errno.EBADF), nil
	}
	vf, ok := f.(*fds.VFSFile)
	if !ok {
		return int64(-errno.ESPIPE), nil
	}
	data, err := proc.MemRead(buf, int(count))
	if err != nil {
		return int64(-errno.EFAULT), nil
	}
	n, err := vf.PwriteAt(data, int64(offset))
	if err != nil {
		return int64(-errno.EIO), nil
	}
	return int64(n), nil
}

func sysReadv(proc Proc, fdNum, iov, iovcnt, _, _, _ uint64) (int64, error) {
	f := proc.Fds().Get(int(fdNum))
	if f == nil {
		return int64(-errno.EBADF), nil
	}
	iovs, err := readIovecs(proc, iov, int(iovcnt))
	if err != nil {
		return int64(-errno.EFAULT), nil
	}
	var total int64
	for _, v := range iovs {
		data, err := f.Read(int(v.length))
		if err != nil {
			// A mid-iovec EAGAIN aborts the whole readv with -EAGAIN
			// only when nothing has been read yet; after partial data,
			// POSIX says return what we have.
			if total > 0 {
				return total, nil
			}
			return int64(-readErrno(err)), nil
		}
		if err := proc.MemWrite(v.base, data); err != nil {
			return int64(-errno.EFAULT), nil
		}
		total += int64(len(data))
		if uint64(len(data)) < v.length {
			break
		}
	}
	return total, nil
}

func sysWritev(proc Proc, fdNum, iov, iovcnt, _, _, _ uint64) (int64, error) {
	f := proc.Fds().Get(int(fdNum))
	if f == nil {
		return int64(-errno.EBADF), nil
	}
	iovs, err := readIovecs(proc, iov, int(iovcnt))
	if err != nil {
		return int64(-errno.EFAULT), nil
	}
	var total int64
	for _, v := range iovs {
		data, err := proc.MemRead(v.base, int(v.length))
		if err != nil {
			return int64(-errno.EFAULT), nil
		}
		n, err := f.Write(data)
		if err != nil {
			return int64(-writeErrno(err)), nil
		}
		total += int64(n)
	}
	return total, nil
}

// --------------------------------------------------------------------------
// open / openat / creat / close
// --------------------------------------------------------------------------

// openCommon implements the shared logic behind open/openat/creat,
// ported from sysemu/syscalls.py's _open_common. O_TMPFILE isn't
// ported yet -- that path falls through to plain VFS-backed file
// behavior instead of the specialized handling the Python version
// has.
func openCommon(proc Proc, path string, flags, mode int) (int64, error) {
	if flags&consts.O_TMPFILE != 0 {
		return openTmpFile(proc, path, flags, mode)
	}
	if flags&consts.O_NOFOLLOW == 0 {
		path = followSymlinks(proc, path)
	}
	// /proc content, for whatever's mounted `-t proc`.
	if rel, ok := procRel(proc, path); ok {
		return openProcfs(proc, path, rel)
	}

	exists := proc.VFS().Exists(path)

	// A chr device node (/dev/null and friends) gets synthetic
	// behavior instead of touching the (nonexistent) backing host
	// file.
	if exists {
		if meta, err := proc.VFS().GetMeta(path); err == nil && meta.Type == "chr" {
			if dev, ok := devices.Open(path, meta.Rdev, proc); ok {
				return int64(proc.Fds().Alloc(dev)), nil
			}
		}
	}

	if !exists {
		if flags&consts.O_CREAT == 0 {
			return int64(-errno.ENOENT), nil
		}
		m := mode & 0o777
		if m == 0 {
			m = 0o644
		}
		if err := proc.VFS().CreateFile(path, m); err != nil {
			return int64(-vfsErrno(err)), nil
		}
	}
	meta, err := proc.VFS().GetMeta(path)
	if err != nil {
		return int64(-vfsErrno(err)), nil
	}
	if meta.Type == "dir" {
		dh, err := fds.NewDirHandle(proc.VFS(), path)
		if err != nil {
			return int64(-vfsErrno(err)), nil
		}
		return int64(proc.Fds().Alloc(dh)), nil
	}
	if flags&consts.O_TRUNC != 0 && exists {
		hp := proc.VFS().HostPath(path)
		if f, err := os.OpenFile(hp, os.O_WRONLY|os.O_TRUNC, 0o644); err == nil {
			f.Close()
		}
	}
	vf, err := fds.OpenVFSFile(proc.VFS(), path, flags)
	if err != nil {
		if os.IsPermission(err) {
			return int64(-errno.EACCES), nil
		}
		if os.IsNotExist(err) {
			return int64(-errno.ENOENT), nil
		}
		return int64(-errno.EIO), nil
	}
	fd := proc.Fds().Alloc(vf)
	if flags&consts.O_CLOEXEC != 0 {
		proc.Fds().SetCloexec(fd, true)
	}
	return int64(fd), nil
}

// openTmpFile implements the O_TMPFILE half of apk's atomic-install
// idiom: an anonymous writable file created inside the directory
// `path` names (per open(2), the pathname argument of an O_TMPFILE
// open is the *directory*, and O_DIRECTORY is implied -- callers that
// forget it get EINVAL like on a real kernel). The fd is a
// *fds.TmpFile; linkat(fd, "", newpath, AT_EMPTY_PATH) in dir.go
// gives it a name later. See vfs.CreateTmpFile/LinkTmpFile.
func openTmpFile(proc Proc, path string, flags, mode int) (int64, error) {
	if flags&consts.O_DIRECTORY == 0 {
		return int64(-errno.EINVAL), nil
	}
	if !proc.VFS().IsDir(path) {
		return int64(-errno.ENOTDIR), nil
	}
	f, hostTmp, err := proc.VFS().CreateTmpFile(path, mode)
	if err != nil {
		return int64(-vfsErrno(err)), nil
	}
	tf := fds.OpenTmpFile(f, hostTmp, mode)
	fd := proc.Fds().Alloc(tf)
	if flags&consts.O_CLOEXEC != 0 {
		proc.Fds().SetCloexec(fd, true)
	}
	return int64(fd), nil
}

func sysOpen(proc Proc, pathPtr, flags, mode, _, _, _ uint64) (int64, error) {
	path, ok := cstr(proc, pathPtr, 4096)
	if !ok {
		return int64(-errno.EFAULT), nil
	}
	return openCommon(proc, resolveAbs(proc, path), int(flags), int(mode))
}

func sysOpenat(proc Proc, dirfd, pathPtr, flags, mode, _, _ uint64) (int64, error) {
	path, ok := cstr(proc, pathPtr, 4096)
	if !ok {
		return int64(-errno.EFAULT), nil
	}
	full, errn := resolve(proc, int32(dirfd), path)
	if errn != 0 {
		return int64(-errn), nil
	}
	return openCommon(proc, full, int(flags), int(mode))
}

func sysCreat(proc Proc, pathPtr, mode, _, _, _, _ uint64) (int64, error) {
	path, ok := cstr(proc, pathPtr, 4096)
	if !ok {
		return int64(-errno.EFAULT), nil
	}
	return openCommon(proc, resolveAbs(proc, path), consts.O_CREAT|consts.O_WRONLY|consts.O_TRUNC, int(mode))
}

func sysClose(proc Proc, fdNum, _, _, _, _, _ uint64) (int64, error) {
	if proc.Fds().Close(int(fdNum)) {
		return 0, nil
	}
	return int64(-errno.EBADF), nil
}

// openProcfs implements the /proc-mounted branch of openCommon.
func openProcfs(proc Proc, path, rel string) (int64, error) {
	if !procfs.Exists(rel, proc) {
		return int64(-errno.ENOENT), nil
	}
	if procfs.IsDir(rel, proc) {
		entries := procfs.Listdir(rel, proc)
		dh := fds.NewDirHandleFromEntries(path, entries)
		return int64(proc.Fds().Alloc(dh)), nil
	}
	if procfs.IsSymlink(rel, proc) {
		// A symlink can't be open()'d directly without O_PATH/O_NOFOLLOW
		// handling this port doesn't model; report ELOOP like a real
		// kernel would for a plain open() hitting a symlink used as a
		// non-final path component elsewhere -- good enough here since
		// callers reach this only via openat() with a literal /proc/*
		// symlink target, an unusual thing to open() directly.
		return int64(-errno.ELOOP), nil
	}
	data, ok := procfs.Read(rel, proc)
	if !ok {
		return int64(-errno.ENOENT), nil
	}
	sf := fds.NewStaticFile(path, data)
	return int64(proc.Fds().Alloc(sf)), nil
}

// --------------------------------------------------------------------------
// lseek / dup / fcntl
// --------------------------------------------------------------------------

func sysLseek(proc Proc, fdNum, offset, whence, _, _, _ uint64) (int64, error) {
	f := proc.Fds().Get(int(fdNum))
	if f == nil || f.IsDir() {
		return int64(-errno.EBADF), nil
	}
	vf, ok := f.(*fds.VFSFile)
	if !ok {
		return int64(-errno.ESPIPE), nil
	}
	newPos, err := vf.Seek(int64(offset), int(whence))
	if err != nil {
		return int64(-errno.EINVAL), nil
	}
	return newPos, nil
}

func sysDup(proc Proc, fdNum, _, _, _, _, _ uint64) (int64, error) {
	newFd, ok := proc.Fds().Dup(int(fdNum))
	if !ok {
		return int64(-errno.EBADF), nil
	}
	return int64(newFd), nil
}

func sysDup2(proc Proc, oldfd, newfd, _, _, _, _ uint64) (int64, error) {
	fd, ok := proc.Fds().Dup2(int(oldfd), int(newfd))
	if !ok {
		return int64(-errno.EBADF), nil
	}
	return int64(fd), nil
}

const fcntlNonblock = 0o4000

// fdCloexec is FD_CLOEXEC, the sole bit F_GETFD/F_SETFD's arg carries.
const fdCloexec = 1

func sysFcntl(proc Proc, fdNum, cmd, arg, _, _, _ uint64) (int64, error) {
	f := proc.Fds().Get(int(fdNum))
	if f == nil {
		return int64(-errno.EBADF), nil
	}
	switch int(cmd) {
	case consts.F_DUPFD:
		return int64(proc.Fds().Alloc(f)), nil
	case consts.F_DUPFD_CLOEXEC:
		newFd := proc.Fds().Alloc(f)
		proc.Fds().SetCloexec(newFd, true)
		return int64(newFd), nil
	case consts.F_GETFD:
		if proc.Fds().Cloexec(int(fdNum)) {
			return fdCloexec, nil
		}
		return 0, nil
	case consts.F_SETFD:
		proc.Fds().SetCloexec(int(fdNum), arg&fdCloexec != 0)
		return 0, nil
	case consts.F_GETFL:
		// Sockets report their real O_NONBLOCK state (polled by
		// musl/glibc connect/accept retry loops to decide whether to
		// block); everything else here never blocks, so 0.
		if g, isSock := f.(*GuestSocket); isSock {
			fl, e := hostSocketGetFlags(g)
			if e != 0 {
				return int64(-int(e)), nil
			}
			return int64(fl & 0o7777), nil
		}
		return 0, nil // regular files are always "blocking" -- never actually blocks here
	case consts.F_SETFL:
		// Forward O_NONBLOCK toggles on sockets to the host, so
		// fcntl(F_SETFL, O_NONBLOCK) after socket() (the portable
		// spelling of SOCK_NONBLOCK) actually takes effect. Only the
		// O_NONBLOCK bit is honored; the guest kernel would accept
		// more, but nothing exercised here sets others on sockets.
		if g, isSock := f.(*GuestSocket); isSock {
			if e := hostSocketSetFlags(g, int(arg&consts.O_NONBLOCK)); e != 0 {
				return int64(-int(e)), nil
			}
			g.f.nonblock = arg&consts.O_NONBLOCK != 0
		}
		return 0, nil
	}
	return 0, nil
}

// --------------------------------------------------------------------------
// pipe
// --------------------------------------------------------------------------

func sysPipe(proc Proc, pipefdPtr, _, _, _, _, _ uint64) (int64, error) {
	return doPipe(proc, pipefdPtr, 0)
}

func sysPipe2(proc Proc, pipefdPtr, flags, _, _, _, _ uint64) (int64, error) {
	return doPipe(proc, pipefdPtr, int(flags))
}

func doPipe(proc Proc, pipefdPtr uint64, flags int) (int64, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return int64(-errno.EMFILE), nil
	}
	rf := &pipeEnd{f: r}
	wf := &pipeEnd{f: w}
	rfd := proc.Fds().Alloc(rf)
	wfd := proc.Fds().Alloc(wf)
	if flags&consts.O_CLOEXEC != 0 {
		proc.Fds().SetCloexec(rfd, true)
		proc.Fds().SetCloexec(wfd, true)
	}
	buf := make([]byte, 8)
	buf[0], buf[1], buf[2], buf[3] = byte(rfd), byte(rfd>>8), byte(rfd>>16), byte(rfd>>24)
	buf[4], buf[5], buf[6], buf[7] = byte(wfd), byte(wfd>>8), byte(wfd>>16), byte(wfd>>24)
	if err := proc.MemWrite(pipefdPtr, buf); err != nil {
		return int64(-errno.EFAULT), nil
	}
	return 0, nil
}

// pipeEnd wraps one end of a real host pipe as a fds.File.
type pipeEnd struct{ f *os.File }

func (p *pipeEnd) Name() string      { return "pipe" }
func (p *pipeEnd) GuestPath() string { return "" }
func (p *pipeEnd) IsDir() bool       { return false }
func (p *pipeEnd) Close() error      { return p.f.Close() }
func (p *pipeEnd) Read(n int) ([]byte, error) {
	buf := make([]byte, n)
	k, err := p.f.Read(buf)
	if k < 0 {
		k = 0
	}
	if err != nil && k == 0 {
		return nil, nil
	}
	return buf[:k], nil
}
func (p *pipeEnd) Write(data []byte) (int, error) { return p.f.Write(data) }
