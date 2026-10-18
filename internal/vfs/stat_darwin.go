//go:build darwin

package vfs

import (
	"os"
	"syscall"
)

// Darwin's syscall.Stat_t differs from Linux's in a few field
// names/types (Mtimespec/Atimespec/Ctimespec instead of Mtim/Atim/
// Ctim; Dev/Rdev are int32 instead of uint64; Nlink is uint16 instead
// of uint64) but describes the same POSIX stat(2) fields, so this is
// otherwise identical to stat_linux.go's extraction.
func extractNativeStat(fi os.FileInfo) nativeStatInfo {
	sys, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nativeStatInfo{}
	}
	return nativeStatInfo{
		uid: sys.Uid, gid: sys.Gid,
		dev: uint64(sys.Dev), ino: sys.Ino, rdev: uint64(sys.Rdev),
		nlink: uint64(sys.Nlink),
		mode:  uint32(sys.Mode),
		mtime: sys.Mtimespec.Sec, atime: sys.Atimespec.Sec, ctime: sys.Ctimespec.Sec,
		ok: true,
	}
}