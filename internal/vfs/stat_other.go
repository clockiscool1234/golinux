//go:build !linux && !darwin

package vfs

import "os"

// extractNativeStat reports ok=false on every platform without a
// POSIX-style struct stat this package knows how to read -- see
// nativeStatInfo's doc comment in stat.go for what callers do with
// that.
func extractNativeStat(fi os.FileInfo) nativeStatInfo {
	return nativeStatInfo{}
}