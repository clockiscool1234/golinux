// Package fds implements a file descriptor table, ported from
// sysemu/fds.py. It covers stdio streams, plain VFS-backed regular
// files, directory handles (for getdents64), and host-backed pipes.
// Sockets are the one entry kind not yet added, alongside the
// syscalls that would need them.
package fds

import (
	"fmt"
	"os"
	"sync"

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

// TmpFile is an O_TMPFILE handle: an anonymous, writable regular file
// the guest can only give a name to via linkat(fd, "", path,
// AT_EMPTY_PATH) -- see vfs.CreateTmpFile/LinkTmpFile and the
// O_TMPFILE branch of syscalls.openCommon. It embeds VFSFile for the
// read/write/seek surface and just adds the bookkeeping linkat needs.
type TmpFile struct {
	VFSFile
	// HostTmp is the anonymous host-side path of the file's content.
	HostTmp string
	// Mode is the mode to register it under when linked into place.
	Mode int
	// Linked records whether a linkat has already consumed this
	// handle: the real kernel allows only one successful
	// linkat(AT_EMPTY_PATH) per O_TMPFILE fd.
	Linked bool
}

// OpenTmpFile wraps an anonymous host file created by
// vfs.CreateTmpFile.
func OpenTmpFile(f *os.File, hostTmp string, mode int) *TmpFile {
	return &TmpFile{
		VFSFile: VFSFile{GuestPathVal: "", f: f},
		HostTmp: hostTmp,
		Mode:    mode,
	}
}

// Close releases the host file. The anonymous content is intentionally
// left on disk (LinkTmpFile removes it on a successful link; an
// abandoned one is indistinguishable from a crash and equally
// harmless) -- removing it here would race a concurrent linkat.
func (t *TmpFile) Close() error { return t.f.Close() }

// fileRefs tracks how many fd-table entries (across every Table
// sharing this *fileRefs -- see Clone) currently reference each open
// File, mirroring the reference count the real kernel keeps on a
// "struct file" (the open file *description*, as opposed to the file
// *descriptor* -- dup()/dup2()/fork() hand out more descriptors
// pointing at the same description without touching its refcount).
//
// Without this, dup2() and fork() (see Clone) alias the very same
// File value across multiple fd numbers, and Table.Close used to call
// f.Close() unconditionally the moment *any* one of those fds was
// closed -- so a shell doing the completely ordinary
// open()+dup2(onto stdout)+close(original) dance to implement "cmd >
// file" would immediately close the underlying *os.File out from
// under the fd it just dup2'd onto stdout, and the write(2) the shell
// builtin then issues to write the redirected output would fail with
// a real I/O error from the OS (since the fd it's holding was already
// closed) -- exactly the "write error: I/O error" a guest shell
// reports for e.g. `echo hi > file`. Reference-counting here so a
// File is only actually closed once its last referencing fd goes away
// fixes that for dup/dup2 and for fork's shared fd tables alike.
type fileRefs struct {
	mu     sync.Mutex
	counts map[File]int
}

func newFileRefs() *fileRefs { return &fileRefs{counts: map[File]int{}} }

func (r *fileRefs) incr(f File) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.counts[f]++
}

// decrAndMaybeClose drops f's refcount by one and, if that was the
// last reference, actually closes it -- outside the lock, since
// File.Close() may block or do I/O.
func (r *fileRefs) decrAndMaybeClose(f File) {
	r.mu.Lock()
	r.counts[f]--
	last := r.counts[f] <= 0
	if last {
		delete(r.counts, f)
	}
	r.mu.Unlock()
	if last {
		_ = f.Close()
	}
}

// Table maps small integers to open files, mirroring Python's
// FDTable.
type Table struct {
	entries map[int]File
	next    int
	refs    *fileRefs

	// cloexec marks which fds carry FD_CLOEXEC (set via open()'s
	// O_CLOEXEC, pipe2()'s O_CLOEXEC, or fcntl(F_SETFD)/
	// F_DUPFD_CLOEXEC) and must be closed by CloseOnExec when this
	// process's image is replaced by execve(). Only true entries are
	// stored; a missing key means "not set", exactly like a real
	// per-fd flag defaulting to clear.
	cloexec map[int]bool
}

// NewTable creates a table with stdin/stdout/stderr already open.
func NewTable() *Table {
	t := &Table{entries: map[int]File{}, next: 3, refs: newFileRefs(), cloexec: map[int]bool{}}
	t.entries[0] = newStdin()
	t.entries[1] = newStdout()
	t.entries[2] = newStderr()
	t.refs.incr(t.entries[0])
	t.refs.incr(t.entries[1])
	t.refs.incr(t.entries[2])
	return t
}

// Get returns the File at fd, or nil if not open.
func (t *Table) Get(fd int) File { return t.entries[fd] }

// SetCloexec sets or clears fd's FD_CLOEXEC flag.
func (t *Table) SetCloexec(fd int, val bool) {
	if val {
		t.cloexec[fd] = true
	} else {
		delete(t.cloexec, fd)
	}
}

// Cloexec reports whether fd currently carries FD_CLOEXEC.
func (t *Table) Cloexec(fd int) bool { return t.cloexec[fd] }

// CloseOnExec closes and removes every fd flagged FD_CLOEXEC, exactly
// what a real execve(2) does to the calling process's fd table before
// the new image starts running. Called by the emulator's execImage.
//
// Without this, a guest program's O_CLOEXEC-opened fds (or ones it
// marked via fcntl(F_SETFD, FD_CLOEXEC)) survive into whatever it
// exec's, even though the guest explicitly asked for them not to.
// That's most visible with shell pipelines: a shell forks a child per
// pipeline stage and relies on FD_CLOEXEC (or explicit close()) to
// keep the pipe's other end from leaking into a stage that doesn't
// need it -- if it leaks in anyway, that stage's own copy of the
// write end keeps the pipe artificially open from its own read()'s
// point of view, and the read blocks forever waiting for a real EOF
// that already happened everywhere else.
func (t *Table) CloseOnExec() {
	for fd, on := range t.cloexec {
		if on {
			t.Close(fd)
		}
	}
}

// Entries returns every currently-open fd number, unordered -- used
// by /proc/self/fd listing.
func (t *Table) Entries() []int {
	out := make([]int, 0, len(t.entries))
	for fd := range t.entries {
		out = append(out, fd)
	}
	return out
}

// Alloc installs f at the next available fd and returns it. Every
// call -- whether f is a brand-new File or one already referenced by
// another fd (as with Dup) -- bumps f's refcount by one, matching the
// new entry this creates.
func (t *Table) Alloc(f File) int {
	fd := t.next
	t.next++
	t.entries[fd] = f
	t.refs.incr(f)
	return fd
}

// Close closes and removes fd, reporting whether it was open. The
// underlying File is only actually closed once its last referencing
// fd (see fileRefs) is gone, so a dup'd/fork-shared fd being closed
// elsewhere can't invalidate this one.
func (t *Table) Close(fd int) bool {
	f, ok := t.entries[fd]
	if !ok {
		return false
	}
	delete(t.entries, fd)
	delete(t.cloexec, fd)
	t.refs.decrAndMaybeClose(f)
	return true
}

// Clone returns a new Table with the same fd numbers pointing at the
// same underlying Files -- the fd-table half of what fork() needs
// (see internal/emulator's doFork). This deliberately duplicates
// entries rather than deep-copying the Files themselves: real
// fork(2) gives the child fds that share the *same* open file
// description (and therefore the same seek offset) as the parent's,
// and since every File here that has a meaningful offset (*VFSFile)
// wraps a real *os.File pointer, copying the map but reusing the same
// File values reproduces exactly that sharing for free. *os.File's
// methods are safe for concurrent use by multiple goroutines, so a
// parent and child both holding it and issuing reads/writes
// concurrently is safe the same way two threads sharing an fd in a
// real process is.
// CloseAll closes and removes every fd still open in this table --
// what a real process's exit(2)/exit_group(2) does to its whole fd
// table before it goes away. Without this, a forked child (see
// Clone) that exits without explicitly close()ing an fd it inherited
// (e.g. a pipeline's writer process, once done, still holds its own
// copy of the pipe's write end as fd 1) never releases that
// reference, so the *fileRefs refcount for that File never reaches
// zero and the real underlying resource (here, the write end of an
// OS pipe) never actually closes -- leaving the reader side blocked
// in read() forever waiting for an EOF that can now never arrive,
// even though every fd a *living* process holds has long since been
// closed.
func (t *Table) CloseAll() {
	for fd := range t.entries {
		t.Close(fd)
	}
}

// Clone returns a new Table sharing the same *fileRefs as t (not a
// fresh one), so the parent's and child's fd tables genuinely share
// reference counts on every File both now point at -- necessary
// because a File closed via the child's Table (e.g. the child closing
// an fd it doesn't need) must not tear down the underlying resource
// while the parent's copy of that same fd is still live, and vice
// versa. Each copied entry's refcount is bumped once for the new
// Table's copy of it.
func (t *Table) Clone() *Table {
	out := &Table{
		entries: make(map[int]File, len(t.entries)),
		next:    t.next,
		refs:    t.refs,
		cloexec: make(map[int]bool, len(t.cloexec)),
	}
	for fd, f := range t.entries {
		out.entries[fd] = f
		t.refs.incr(f)
	}
	for fd, on := range t.cloexec {
		out.cloexec[fd] = on
	}
	return out
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
		t.refs.incr(f)
	}
	if newfd+1 > t.next {
		t.next = newfd + 1
	}
	return newfd, true
}
