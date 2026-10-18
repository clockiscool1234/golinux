//go:build linux

package vfs

import (
	"os"
	"syscall"
)

func extractNativeStat(fi os.FileInfo) nativeStatInfo {
	sys, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nativeStatInfo{}
	}
	return nativeStatInfo{
		uid: sys.Uid, gid: sys.Gid,
		dev: uint64(sys.Dev), ino: sys.Ino, rdev: sys.Rdev,
		nlink: uint64(sys.Nlink),
		mode:  sys.Mode,
		mtime: sys.Mtim.Sec, atime: sys.Atim.Sec, ctime: sys.Ctim.Sec,
		ok: true,
	}
}