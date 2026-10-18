package vfs

// Linux stat(2) mode type bits (the S_IF* family). These describe the
// *guest's* Linux stat() ABI, not whatever the host happens to define
// in its own syscall package -- POSIX standardizes these exact
// numeric values, so every real Unix (Linux, the BSDs, macOS) agrees
// on them regardless of host GOOS, but a non-Unix host (Windows) may
// not define them at all. Hardcoding them here means vfs.go never
// needs to reach into the host's syscall package just to describe the
// guest's own file-type bits.
const (
	modeIFIFO  = 0010000
	modeIFCHR  = 0020000
	modeIFDIR  = 0040000
	modeIFBLK  = 0060000
	modeIFREG  = 0100000
	modeIFLNK  = 0120000
	modeIFSOCK = 0140000
)

// nativeStatInfo holds OS-native metadata extracted from an
// os.FileInfo's Sys() value, when the host platform exposes one in a
// form this package knows how to read (see stat_linux.go and
// stat_darwin.go). ok is false on any platform without a POSIX-style
// struct stat to read at all (stat_other.go -- Windows, and any
// future GOOS this project gets built for); callers synthesize the
// same kind of stable, sensible metadata the non-NativePerms metadata
// path elsewhere in this package already computes (stable per-path
// inode, Dev=1, Uid/Gid=0, Nlink derived from file type) rather than
// failing every stat(2)/lstat(2) outright -- there's no real notion
// of uid/gid/device nodes/hardlink counts for this emulator to report
// accurately on a platform without them anyway, so synthesizing is
// the honest answer, not a regression from something more-correct
// this platform could otherwise have had.
type nativeStatInfo struct {
	uid, gid       uint32
	dev, ino, rdev uint64
	nlink          uint64
	mode           uint32 // raw host st_mode: type bits + permission bits, already correct as-is
	mtime          int64
	atime          int64
	ctime          int64
	ok             bool
}

// extractNativeStat is implemented per-platform: stat_linux.go and
// stat_darwin.go for the two OSes with a real syscall.Stat_t this
// package reads directly, stat_other.go (ok=false, zero value) for
// everything else.