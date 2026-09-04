package syscalls

import (
	"encoding/binary"
	"strings"

	"golinux/internal/consts"
	"golinux/internal/errno"
	"golinux/internal/vfs"
)

const pageSize = consts.PageSize

// cstr reads a NUL-terminated string from guest memory at addr,
// ported from sysemu/syscalls.py's _cstr. Reads a page at a time so a
// string near the edge of a small mapping never over-reads into
// unmapped memory in a single call. Returns ok=false if addr is 0.
func cstr(proc Proc, addr uint64, maxlen int) (string, bool) {
	if addr == 0 {
		return "", false
	}
	if maxlen <= 0 {
		maxlen = 4096
	}
	var data []byte
	cur := addr
	for len(data) < maxlen {
		pageEnd := (cur/pageSize + 1) * pageSize
		chunkLen := maxlen - len(data)
		if want := int(pageEnd - cur); want < chunkLen {
			chunkLen = want
		}
		chunk, err := proc.MemRead(cur, chunkLen)
		if err != nil {
			break
		}
		if idx := indexZero(chunk); idx != -1 {
			data = append(data, chunk[:idx]...)
			return string(data), true
		}
		data = append(data, chunk...)
		cur += uint64(chunkLen)
	}
	return string(data), true
}

func indexZero(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return -1
}

// readCStrArray reads a NULL-terminated array of guest pointers, each
// pointing to a C string -- the argv/envp layout execve() receives.
func readCStrArray(proc Proc, ptr uint64) []string {
	if ptr == 0 {
		return nil
	}
	var out []string
	i := uint64(0)
	for {
		raw, err := proc.MemRead(ptr+i*8, 8)
		if err != nil {
			break
		}
		p := binary.LittleEndian.Uint64(raw)
		if p == 0 {
			break
		}
		s, _ := cstr(proc, p, 4096)
		out = append(out, s)
		i++
	}
	return out
}

// iovec mirrors struct iovec { void *iov_base; size_t iov_len; }.
type iovec struct {
	base   uint64
	length uint64
}

func readIovecs(proc Proc, iov uint64, iovcnt int) ([]iovec, error) {
	out := make([]iovec, 0, iovcnt)
	for i := 0; i < iovcnt; i++ {
		data, err := proc.MemRead(iov+uint64(i)*16, 16)
		if err != nil {
			return nil, err
		}
		out = append(out, iovec{
			base:   binary.LittleEndian.Uint64(data[0:8]),
			length: binary.LittleEndian.Uint64(data[8:16]),
		})
	}
	return out, nil
}

// resolve turns an (dirfd, path) pair -- the pattern every *at()
// syscall uses -- into an absolute guest path, ported from
// sysemu/syscalls.py's _resolve.
func resolve(proc Proc, dirfd int32, path string) (string, int) {
	if strings.HasPrefix(path, "/") {
		return path, 0
	}
	var base string
	if dirfd == consts.AT_FDCWD {
		base = proc.Cwd()
	} else {
		f := proc.Fds().Get(int(dirfd))
		if f == nil {
			return "", errno.EBADF
		}
		base = f.GuestPath()
		if base == "" {
			return "", errno.EBADF
		}
	}
	if path == "" {
		return base, 0
	}
	return strings.TrimRight(base, "/") + "/" + path, 0
}

// followSymlinks resolves a path through any VFS-level symlinks along
// the way (both the final component and any intermediate directory),
// the way a real path lookup would. Ported from sysemu/syscalls.py's
// _follow_symlinks, minus the /proc-specific branch (procfs paths are
// synthetic and have no VFS-level symlinks to resolve).
func followSymlinks(proc Proc, path string) string {
	if path == "" {
		return path
	}
	const maxHops = 40
	for hops := 0; hops < maxHops; hops++ {
		parts := strings.Split(path, "/")
		var resolvedParts []string
		changed := false

		for i, part := range parts {
			if part == "" || part == "." {
				continue
			}
			if part == ".." {
				if len(resolvedParts) > 0 {
					resolvedParts = resolvedParts[:len(resolvedParts)-1]
				}
				continue
			}
			resolvedParts = append(resolvedParts, part)
			currentPath := joinAbs(path, resolvedParts)

			isLink := false
			target := ""
			if proc.VFS().Exists(currentPath) {
				if meta, err := proc.VFS().GetMeta(currentPath); err == nil && meta.Type == "lnk" {
					isLink = true
					target = meta.Target
				}
			}

			if isLink {
				changed = true
				rest := strings.Join(parts[i+1:], "/")
				var remPath string
				if strings.HasPrefix(target, "/") {
					remPath = target + "/" + rest
				} else {
					parent := joinAbs(path, resolvedParts[:len(resolvedParts)-1])
					if parent == "" && !strings.HasPrefix(path, "/") {
						remPath = target + "/" + rest
					} else {
						remPath = parent + "/" + target + "/" + rest
					}
				}
				path = collapseSlashes(remPath)
				if path != "/" {
					path = strings.TrimRight(path, "/")
				}
				break
			}
		}

		if !changed {
			final := joinAbs(path, resolvedParts)
			if final == "" {
				return "/"
			}
			return final
		}
	}
	return path
}

func joinAbs(orig string, parts []string) string {
	prefix := ""
	if strings.HasPrefix(orig, "/") {
		prefix = "/"
	}
	return prefix + strings.Join(parts, "/")
}

func collapseSlashes(s string) string {
	for strings.Contains(s, "//") {
		s = strings.ReplaceAll(s, "//", "/")
	}
	return s
}

// vfsErrno extracts the errno from a *vfs.VFSError, or falls back to
// EIO for any other error.
func vfsErrno(err error) int {
	if err == nil {
		return 0
	}
	if ve, ok := err.(*vfs.VFSError); ok {
		return ve.Errno
	}
	return errno.EIO
}

// procRel reports whether path falls under a `mount -t proc`'d
// mountpoint, returning the path relative to that mountpoint if so.
// Ported from sysemu/syscalls.py's _proc_rel.
func procRel(proc Proc, path string) (string, bool) {
	if proc.VFS().MountType(path) != "proc" {
		return "", false
	}
	mp := strings.TrimSuffix(proc.VFS().MountPointFor(path), "/")
	rel := strings.TrimPrefix(path, mp)
	rel = strings.TrimPrefix(rel, "/")
	return rel, true
}
