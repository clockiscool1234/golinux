// Package fds implements a file descriptor table, ported from
// sysemu/fds.py. It covers stdio streams, plain VFS-backed regular
// files, directory handles (for getdents64), and host-backed pipes.
// Sockets are the one entry kind not yet added, alongside the
// syscalls that would need them.
package fds

import (
	"fmt"
	"os"

	"golinux/internal/vfs"
)

// File is anything that can live in the fd table.
type File interface {
	Read(n int) ([]byte, error)
	Write(data []byte) (int, error)
	Close() error
	// Name identifies stdio streams ("stdin"/"stdout"/"stderr") for
	// syscalls (like ioctl) that special-case them; "" otherwise.
	Name() string
	// GuestPath is the VFS path backing this fd, or "" if none (stdio,
	// pipes, sockets).
	GuestPath() string
	// IsDir reports whether this fd was opened on a directory (see
	// DirHandle) rather than a regular file/stream.
	IsDir() bool
}

// StreamDev is a simple stdio-backed or black-hole pseudo device.
type StreamDev struct {
	name    string
	readFn  func(n int) ([]byte, error)
	writeFn func(data []byte) (int, error)
}

func (s *StreamDev) Name() string      { return s.name }
func (s *StreamDev) GuestPath() string { return "" }
func (s *StreamDev) IsDir() bool       { return false }

func (s *StreamDev) Read(n int) ([]byte, error) {
	if s.readFn == nil {
		return nil, nil
	}
	return s.readFn(n)
}

func (s *StreamDev) Write(data []byte) (int, error) {
	if s.writeFn == nil {
		return len(data), nil
	}
	return s.writeFn(data)
}

func (s *StreamDev) Close() error { return nil }

// NewStreamDev builds a StreamDev from the given name and read/write
// functions -- the public constructor other packages (e.g. devices,
// for /dev/null-style nodes) use to build their own pseudo-devices
// without reaching into this package's internals.
func NewStreamDev(name string, readFn func(n int) ([]byte, error), writeFn func(data []byte) (int, error)) *StreamDev {
	return &StreamDev{name: name, readFn: readFn, writeFn: writeFn}
}

// ErrnoError lets a File's Read/Write report a specific errno (rather
// than the generic EIO callers fall back to for a plain error), e.g.
// /dev/full reporting ENOSPC on every write.
type ErrnoError struct{ Errno int }

func (e *ErrnoError) Error() string { return "errno" }

func newStdin() *StreamDev {
	return &StreamDev{name: "stdin", readFn: func(n int) ([]byte, error) {
		if n <= 0 {
			return nil, nil
		}
		buf := make([]byte, n)
		k, err := os.Stdin.Read(buf)
		if k < 0 {
			k = 0
		}
		if err != nil {
			return buf[:k], nil // EOF etc. surfaces as a short/zero read, matching read(2)
		}
		return buf[:k], nil
	}}
}

func newStdout() *StreamDev {
	return &StreamDev{name: "stdout", writeFn: func(data []byte) (int, error) {
		return os.Stdout.Write(data)
	}}
}

func newStderr() *StreamDev {
	return &StreamDev{name: "stderr", writeFn: func(data []byte) (int, error) {
		return os.Stderr.Write(data)
	}}
}

// VFSFile is a real, seekable file living in the VirtualFileSystem.
type VFSFile struct {
	GuestPathVal string
	f            *os.File
}

func (v *VFSFile) Name() string      { return "" }
func (v *VFSFile) GuestPath() string { return v.GuestPathVal }
func (v *VFSFile) IsDir() bool       { return false }

func (v *VFSFile) Read(n int) ([]byte, error) {
	buf := make([]byte, n)
	k, err := v.f.Read(buf)
	if k < 0 {
		k = 0
	}
	if err != nil && k == 0 {
		return nil, nil // EOF -> empty read, not an error, matching Python's f.read(n)
	}
	return buf[:k], nil
}

func (v *VFSFile) Write(data []byte) (int, error) {
	// Go's *os.File is unbuffered (writes go straight to the OS), so
	// unlike Python's buffered io wrapper this needs no explicit
	// flush to make the data visible to a concurrent reader/mmap.
	return v.f.Write(data)
}

func (v *VFSFile) Close() error { return v.f.Close() }

// Seek repositions the file and returns the new absolute offset,
// matching lseek(2)'s return convention.
func (v *VFSFile) Seek(offset int64, whence int) (int64, error) {
	return v.f.Seek(offset, whence)
}

// PreadAt reads up to n bytes at a fixed offset without disturbing
// the file's current seek position (used by mmap()).
func (v *VFSFile) PreadAt(n int, offset int64) ([]byte, error) {
	buf := make([]byte, n)
	k, err := v.f.ReadAt(buf, offset)
	if k < 0 {
		k = 0
	}
	if err != nil && k == 0 {
		return nil, nil
	}
	return buf[:k], nil
}

// StaticFile is a read-only fd backed by an in-memory byte slice,
// generated fresh at open() time -- used for synthetic /proc content
// (see the procfs package). Writes report EROFS, matching a real
// read-only /proc mount.
type StaticFile struct {
	GuestPathVal string
	data         []byte
	pos          int
}

// NewStaticFile wraps data as a read-only fd at guestPath.
func NewStaticFile(guestPath string, data []byte) *StaticFile {
	return &StaticFile{GuestPathVal: guestPath, data: data}
}

func (f *StaticFile) Name() string      { return "" }
func (f *StaticFile) GuestPath() string { return f.GuestPathVal }
func (f *StaticFile) IsDir() bool       { return false }
func (f *StaticFile) Close() error      { return nil }

func (f *StaticFile) Read(n int) ([]byte, error) {
	if f.pos >= len(f.data) {
		return nil, nil
	}
	end := f.pos + n
	if end > len(f.data) {
		end = len(f.data)
	}
	out := f.data[f.pos:end]
	f.pos = end
	return out, nil
}

// PreadAt reads at a fixed offset without disturbing the read cursor,
// mirroring ProcFile.pread in sysemu/procfs.py.
func (f *StaticFile) PreadAt(n int, offset int64) ([]byte, error) {
	if offset < 0 || int(offset) >= len(f.data) {
		return nil, nil
	}
	end := int(offset) + n
	if end > len(f.data) {
		end = len(f.data)
	}
	return f.data[offset:end], nil
}

func (f *StaticFile) Write(data []byte) (int, error) {
	return 0, &ErrnoError{Errno: 30} // EROFS
}

// DirHandle represents an fd opened on a directory (for getdents64).
// Entries are snapshotted at open time, matching Python's DirHandle.
type DirHandle struct {
	GuestPathVal string
	entries      []string
	Pos          int
}

// NewDirHandle lists guestPath via vv and returns a DirHandle
// positioned at the start, including the synthetic "." and ".."
// entries every directory has.
func NewDirHandle(vv *vfs.VFS, guestPath string) (*DirHandle, error) {
	names, err := vv.Listdir(guestPath)
	if err != nil {
		return nil, err
	}
	entries := append([]string{".", ".."}, names...)
	return &DirHandle{GuestPathVal: guestPath, entries: entries}, nil
}

// NewDirHandleFromEntries builds a DirHandle from an already-computed
// entry list (used for synthetic directories like /proc, which have
// no real host directory to list).
func NewDirHandleFromEntries(guestPath string, names []string) *DirHandle {
	entries := append([]string{".", ".."}, names...)
	return &DirHandle{GuestPathVal: guestPath, entries: entries}
}

func (d *DirHandle) Entries() []string { return d.entries }
func (d *DirHandle) Name() string      { return "" }
func (d *DirHandle) GuestPath() string { return d.GuestPathVal }
func (d *DirHandle) IsDir() bool       { return true }
func (d *DirHandle) Close() error      { return nil }
func (d *DirHandle) Read(n int) ([]byte, error) {
	return nil, fmt.Errorf("is a directory")
}
func (d *DirHandle) Write(data []byte) (int, error) {
	return 0, fmt.Errorf("is a directory")
}

// Truncate resizes the underlying file.
func (v *VFSFile) Truncate(size int64) error {
	return v.f.Truncate(size)
}

// PwriteAt writes data at a fixed offset without disturbing the
// file's current seek position.
func (v *VFSFile) PwriteAt(data []byte, offset int64) (int, error) {
	return v.f.WriteAt(data, offset)
}

// OpenVFSFile opens (or creates, per flags) a regular file through
// the VFS and wraps it as a fds.File.
func OpenVFSFile(vv *vfs.VFS, guestPath string, flags int) (*VFSFile, error) {
	hp := vv.HostPath(guestPath)
	osFlags := os.O_RDWR
	switch flags & 0o3 {
	case 0:
		osFlags = os.O_RDONLY
	case 1:
		osFlags = os.O_WRONLY
	case 2:
		osFlags = os.O_RDWR
	}
	if flags&0o100 != 0 { // O_CREAT
		osFlags |= os.O_CREATE
	}
	if flags&0o1000 != 0 { // O_TRUNC
		osFlags |= os.O_TRUNC
	}
	if flags&0o2000 != 0 { // O_APPEND
		osFlags |= os.O_APPEND
	}
	f, err := os.OpenFile(hp, osFlags, 0o644)
	if err != nil {
		return nil, err
	}
	return &VFSFile{GuestPathVal: guestPath, f: f}, nil
}

// Table maps small integers to open files, mirroring Python's
// FDTable.
type Table struct {
	entries map[int]File
	next    int
}

// NewTable creates a table with stdin/stdout/stderr already open.
func NewTable() *Table {
	t := &Table{entries: map[int]File{}, next: 3}
	t.entries[0] = newStdin()
	t.entries[1] = newStdout()
	t.entries[2] = newStderr()
	return t
}

// Get returns the File at fd, or nil if not open.
func (t *Table) Get(fd int) File { return t.entries[fd] }

// Entries returns every currently-open fd number, unordered -- used
// by /proc/self/fd listing.
func (t *Table) Entries() []int {
	out := make([]int, 0, len(t.entries))
	for fd := range t.entries {
		out = append(out, fd)
	}
	return out
}

// Alloc installs f at the next available fd and returns it.
func (t *Table) Alloc(f File) int {
	fd := t.next
	t.next++
	t.entries[fd] = f
	return fd
}

// Close closes and removes fd, reporting whether it was open.
func (t *Table) Close(fd int) bool {
	f, ok := t.entries[fd]
	if !ok {
		return false
	}
	delete(t.entries, fd)
	_ = f.Close()
	return true
}

// Dup allocates a new fd pointing at the same File as oldfd.
func (t *Table) Dup(oldfd int) (int, bool) {
	f, ok := t.entries[oldfd]
	if !ok {
		return 0, false
	}
	return t.Alloc(f), true
}

// Dup2 makes newfd point at the same File as oldfd (closing any
// previous occupant of newfd).
func (t *Table) Dup2(oldfd, newfd int) (int, bool) {
	f, ok := t.entries[oldfd]
	if !ok {
		return 0, false
	}
	if newfd != oldfd {
		if _, occupied := t.entries[newfd]; occupied {
			t.Close(newfd)
		}
		t.entries[newfd] = f
	}
	if newfd+1 > t.next {
		t.next = newfd + 1
	}
	return newfd, true
}
