// Package vfs is a cross-platform virtual filesystem, ported from
// sysemu/vfs.py.
//
// Design
// ------
// The VFS is rooted at a real host directory (Root). Every guest
// directory maps 1:1 onto a real host directory under Root, and
// regular file *content* is simply stored as a regular host file --
// reading/writing bytes works identically on Linux, macOS and Windows,
// so we lean on the host filesystem for that part.
//
// What we do NOT lean on the host for is ownership/permission bits,
// because:
//   - Windows has no uid/gid and only a coarse read-only bit.
//   - Even on POSIX hosts, chmod/chown would require running as root to
//     fake arbitrary uid/gid, and would pollute a real filesystem with
//     guest-owned files.
//
// Instead, every directory carries a JSON sidecar file named
// ".pylinux_meta" holding metadata for each entry *inside* that
// directory: {name: {"type": "reg"|"dir"|"lnk"|"chr"|"blk"|"fifo",
// "mode": int, "uid": int, "gid": int, "target": str|null}}.
// The directory's own metadata lives in its *parent's* sidecar file,
// under its own name; the vfs root's metadata lives in a sidecar file
// placed directly inside Root, under the special key ".".
//
// Symlinks are pure metadata (a "lnk" entry with a "target" string) --
// no real symlink is ever created on the host, so this works the same
// on Windows and POSIX and never needs elevated privileges.
//
// Self-healing: any real file or directory found on the host with no
// corresponding sidecar entry (dropped in manually, or left behind after
// a sidecar was deleted) is automatically registered as root:root with
// full permissions (0o777) the next time that directory is looked at --
// see reconcile().
package vfs

import (
	"crypto/md5"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	Sidecar         = ".golinux_meta"
	LegacySidecar   = ".pylinux_meta" // auto-migrated on first access, see loadSidecar
	DefaultDirMode  = 0o755
	DefaultFileMode = 0o644
	AutohealMode    = 0o777
)

// VFSError carries a Linux errno-style code, mirroring the Python
// VFSError exception.
type VFSError struct {
	Errno int
	Msg   string
}

func (e *VFSError) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	return "errno " + itoa(e.Errno)
}

func newErr(errno int, msg string) *VFSError { return &VFSError{Errno: errno, Msg: msg} }

func itoa(n int) string {
	// tiny local itoa to avoid importing strconv just for this
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// Meta is the per-entry metadata record stored in sidecar files.
type Meta struct {
	Type   string `json:"type"`
	Mode   int    `json:"mode"`
	Uid    int    `json:"uid"`
	Gid    int    `json:"gid"`
	Target string `json:"target,omitempty"`
	Rdev   int    `json:"rdev,omitempty"`
}

// Stat mirrors the dict returned by VirtualFileSystem.stat() in Python.
type Stat struct {
	Dev   uint64
	Ino   uint64
	Mode  uint32 // includes type bits, like st_mode
	Size  int64
	Uid   uint32
	Gid   uint32
	Mtime int64
	Atime int64
	Ctime int64
	Nlink uint64
	Rdev  uint64
}

// MountInfo is one row of the mount table.
type MountInfo struct {
	Source string `json:"source"`
	Fstype string `json:"fstype"`
	Flags  int    `json:"flags"`
	Data   string `json:"data"`
}

// MountRow is a MountInfo with its mountpoint path, for /proc/mounts.
type MountRow struct {
	Path string
	MountInfo
}

// normPath normalizes a guest absolute path: collapse . / .. / //
// without touching the host filesystem at all (pure string algebra).
func normPath(path string) string {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	comps := strings.Split(path, "/")
	parts := make([]string, 0, len(comps))
	for _, c := range comps {
		if c == "" || c == "." {
			continue
		}
		if c == ".." {
			if len(parts) > 0 {
				parts = parts[:len(parts)-1]
			}
			continue
		}
		parts = append(parts, c)
	}
	return "/" + strings.Join(parts, "/")
}

// VFS is the virtual filesystem.
type VFS struct {
	Root        string
	NativePerms bool

	// mu guards mounts/mountsMTime. A single *VFS is shared by every
	// process in a fork() tree (fork gives the child the same mount
	// namespace as the parent -- see internal/emulator's doFork), so
	// once a guest program forks, this map can genuinely be read and
	// written from more than one goroutine at the same time; every
	// method that touches it below takes mu for its whole body.
	mu          sync.Mutex
	mounts      map[string]MountInfo
	mountsMTime int64 // ns; -1 means "no file seen yet"
}

// New creates (or opens) a VFS rooted at root.
func New(root string, nativePerms bool) (*VFS, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return nil, err
	}
	v := &VFS{
		Root:        abs,
		NativePerms: nativePerms,
		mounts:      map[string]MountInfo{},
		mountsMTime: -1,
	}
	if !nativePerms {
		if err := v.ensureRootMeta(); err != nil {
			return nil, err
		}
	}
	v.refreshMounts()
	return v, nil
}

// RefreshMounts is the public entrypoint for callers outside this
// package (e.g. the syscalls package) that need to consult the mount
// table directly instead of going through MountType()/MountPointFor().
func (v *VFS) RefreshMounts() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.refreshMounts()
}

func (v *VFS) mountsFile() string {
	return filepath.Join(v.Root, ".golinux_mounts.json")
}

func (v *VFS) legacyMountsFile() string {
	return filepath.Join(v.Root, ".pylinux_mounts.json")
}

// migrateLegacyMountsFile renames the old pylinux-era mounts file to
// the new name the first time it's seen, so existing vfs roots keep
// working without any manual conversion step.
func (v *VFS) migrateLegacyMountsFile() {
	newPath := v.mountsFile()
	if _, err := os.Stat(newPath); err == nil {
		return // already migrated (or created fresh under the new name)
	}
	oldPath := v.legacyMountsFile()
	if _, err := os.Stat(oldPath); err != nil {
		return // nothing to migrate
	}
	_ = os.Rename(oldPath, newPath)
}

func (v *VFS) refreshMounts() {
	v.migrateLegacyMountsFile()
	path := v.mountsFile()
	st, err := os.Stat(path)
	if err != nil {
		if len(v.mounts) != 0 {
			v.mounts = map[string]MountInfo{}
		}
		v.mountsMTime = -1
		return
	}
	mtimeNs := st.ModTime().UnixNano()
	if mtimeNs == v.mountsMTime {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		v.mounts = map[string]MountInfo{}
		v.mountsMTime = mtimeNs
		return
	}
	var m map[string]MountInfo
	if err := json.Unmarshal(data, &m); err != nil {
		v.mounts = map[string]MountInfo{}
	} else {
		v.mounts = m
	}
	v.mountsMTime = mtimeNs
}

func (v *VFS) persistMounts() error {
	path := v.mountsFile()
	tmp := path + ".tmp"
	data, err := json.Marshal(v.mounts)
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	st, err := os.Stat(path)
	if err == nil {
		v.mountsMTime = st.ModTime().UnixNano()
	}
	return nil
}

// -- host path mapping ------------------------------------------------

// HostPath maps a guest path to its backing host path.
func (v *VFS) HostPath(guestPath string) string {
	guestPath = normPath(guestPath)
	rel := strings.TrimPrefix(guestPath, "/")
	if rel == "" {
		return v.Root
	}
	return filepath.Join(v.Root, filepath.FromSlash(rel))
}

// -- sidecar handling ---------------------------------------------------

func sidecarPath(hostDir string) string {
	return filepath.Join(hostDir, Sidecar)
}

func legacySidecarPath(hostDir string) string {
	return filepath.Join(hostDir, LegacySidecar)
}

// migrateLegacySidecar renames a directory's old pylinux-era
// .pylinux_meta file to .golinux_meta the first time that directory
// is touched, so a vfs root created by the previous version of this
// tool keeps working with zero manual conversion. No-op once migrated
// (or if the directory was always golinux-native).
func migrateLegacySidecar(hostDir string) {
	newPath := sidecarPath(hostDir)
	if _, err := os.Stat(newPath); err == nil {
		return
	}
	oldPath := legacySidecarPath(hostDir)
	if _, err := os.Stat(oldPath); err != nil {
		return
	}
	_ = os.Rename(oldPath, newPath)
}

func loadSidecar(hostDir string) map[string]Meta {
	migrateLegacySidecar(hostDir)
	p := sidecarPath(hostDir)
	data, err := os.ReadFile(p)
	if err != nil {
		return map[string]Meta{}
	}
	var m map[string]Meta
	if err := json.Unmarshal(data, &m); err != nil {
		return map[string]Meta{}
	}
	if m == nil {
		m = map[string]Meta{}
	}
	return m
}

func saveSidecar(hostDir string, data map[string]Meta) error {
	p := sidecarPath(hostDir)
	tmp := p + ".tmp"
	b, err := json.MarshalIndent(data, "", " ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

func (v *VFS) ensureRootMeta() error {
	data := loadSidecar(v.Root)
	if _, ok := data["."]; !ok {
		data["."] = Meta{Type: "dir", Mode: DefaultDirMode}
		return saveSidecar(v.Root, data)
	}
	return nil
}

// reconcile makes sure every real file/dir sitting in hostDir (found on
// disk, e.g. dropped in manually or left behind after the sidecar was
// deleted) has a metadata entry. Anything missing gets auto-registered
// as root:root with full permissions (0o777) -- never left "invisible"
// just because metadata never existed.
func (v *VFS) reconcile(hostDir string) map[string]Meta {
	data := loadSidecar(hostDir)
	entries, err := os.ReadDir(hostDir)
	var names []string
	if err == nil {
		for _, e := range entries {
			names = append(names, e.Name())
		}
	}
	changed := false
	for _, name := range names {
		if name == Sidecar || name == LegacySidecar || strings.HasSuffix(name, ".tmp") {
			continue
		}
		if _, ok := data[name]; ok {
			continue
		}
		full := filepath.Join(hostDir, name)
		fi, lerr := os.Lstat(full)
		if lerr == nil && fi.Mode()&os.ModeSymlink != 0 {
			target, rerr := os.Readlink(full)
			if rerr != nil {
				target = ""
			}
			data[name] = Meta{Type: "lnk", Mode: AutohealMode, Target: target}
		} else {
			typ := "reg"
			if lerr == nil && fi.IsDir() {
				typ = "dir"
			}
			data[name] = Meta{Type: typ, Mode: AutohealMode}
		}
		changed = true
	}
	if _, ok := data["."]; !ok && hostDir == v.Root {
		data["."] = Meta{Type: "dir", Mode: DefaultDirMode}
		changed = true
	}
	if changed {
		_ = saveSidecar(hostDir, data)
	}
	return data
}

// -- metadata get/set ---------------------------------------------------

func typeFromMode(m os.FileMode) string {
	switch {
	case m&os.ModeSymlink != 0:
		return "lnk"
	case m.IsDir():
		return "dir"
	case m&os.ModeCharDevice != 0:
		return "chr"
	case m&os.ModeDevice != 0:
		return "blk"
	case m&os.ModeNamedPipe != 0:
		return "fifo"
	case m.IsRegular():
		return "reg"
	default:
		return "reg"
	}
}

func (v *VFS) nativeGetMeta(guestPath string) (Meta, error) {
	hp := v.HostPath(guestPath)
	fi, err := os.Lstat(hp)
	if err != nil {
		if os.IsNotExist(err) {
			return Meta{}, newErr(2, "no such file: "+guestPath)
		}
		if os.IsPermission(err) {
			return Meta{}, newErr(13, "permission denied: "+guestPath)
		}
		return Meta{}, newErr(5, err.Error())
	}
	typ := typeFromMode(fi.Mode())
	target := ""
	if typ == "lnk" {
		t, rerr := os.Readlink(hp)
		if rerr == nil {
			target = t
		}
	}
	var rdev uint64
	uid, gid := 0, 0
	if sys, ok := fi.Sys().(*syscall.Stat_t); ok {
		uid = int(sys.Uid)
		gid = int(sys.Gid)
		if typ == "chr" || typ == "blk" {
			rdev = sys.Rdev
		}
	}
	return Meta{
		Type:   typ,
		Mode:   int(fi.Mode().Perm()),
		Uid:    uid,
		Gid:    gid,
		Target: target,
		Rdev:   int(rdev),
	}, nil
}

// GetMeta returns the metadata for guestPath.
func (v *VFS) GetMeta(guestPath string) (Meta, error) {
	guestPath = normPath(guestPath)
	if v.NativePerms {
		return v.nativeGetMeta(guestPath)
	}
	if guestPath == "/" {
		data := loadSidecar(v.Root)
		if _, ok := data["."]; !ok {
			_ = v.ensureRootMeta()
			data = loadSidecar(v.Root)
		}
		return data["."], nil
	}
	parent, name := splitGuest(guestPath)
	hostParent := v.HostPath(parent)
	data := v.reconcile(hostParent)
	m, ok := data[name]
	if !ok {
		return Meta{}, newErr(2, "no metadata for "+guestPath)
	}
	return m, nil
}

// splitGuest splits a normalized guest path into (parent, name),
// mirroring Python's guest_path.rsplit("/", 1) with parent defaulting
// to "/".
func splitGuest(guestPath string) (string, string) {
	idx := strings.LastIndex(guestPath, "/")
	parent := guestPath[:idx]
	name := guestPath[idx+1:]
	if parent == "" {
		parent = "/"
	}
	return parent, name
}

// SetMeta updates (merges) metadata fields for guestPath. Pass a
// function that mutates the existing (or default) Meta in place.
func (v *VFS) SetMeta(guestPath string, update func(*Meta)) error {
	guestPath = normPath(guestPath)
	if guestPath == "/" {
		data := loadSidecar(v.Root)
		m := data["."]
		update(&m)
		data["."] = m
		return saveSidecar(v.Root, data)
	}
	parent, name := splitGuest(guestPath)
	hostParent := v.HostPath(parent)
	data := loadSidecar(hostParent)
	m, ok := data[name]
	if !ok {
		m = Meta{Type: "reg", Mode: DefaultFileMode}
	}
	update(&m)
	data[name] = m
	return saveSidecar(hostParent, data)
}

func (v *VFS) register(guestPath, typ string, mode int, target string, rdev int) error {
	parent, name := splitGuest(normPath(guestPath))
	hostParent := v.HostPath(parent)
	data := loadSidecar(hostParent)
	entry := Meta{Type: typ, Mode: mode}
	entry.Target = target
	entry.Rdev = rdev
	data[name] = entry
	return saveSidecar(hostParent, data)
}

func (v *VFS) unregister(guestPath string) error {
	parent, name := splitGuest(normPath(guestPath))
	hostParent := v.HostPath(parent)
	data := loadSidecar(hostParent)
	delete(data, name)
	return saveSidecar(hostParent, data)
}

// -- existence / type checks ---------------------------------------------

// Exists reports whether guestPath exists in the VFS.
func (v *VFS) Exists(guestPath string) bool {
	if v.NativePerms {
		_, err := os.Lstat(v.HostPath(guestPath))
		return err == nil
	}
	_, err := v.GetMeta(guestPath)
	return err == nil
}

// IsDir reports whether guestPath is a directory.
func (v *VFS) IsDir(guestPath string) bool {
	if v.NativePerms {
		fi, err := os.Stat(v.HostPath(guestPath))
		return err == nil && fi.IsDir()
	}
	m, err := v.GetMeta(guestPath)
	return err == nil && m.Type == "dir"
}

// -- directory operations -------------------------------------------------

// Mkdir creates a single directory (like Python's mkdir()).
func (v *VFS) Mkdir(guestPath string, mode int) error {
	if v.Exists(guestPath) {
		return newErr(17, "") // EEXIST
	}
	hp := v.HostPath(guestPath)
	if err := os.MkdirAll(hp, 0o755); err != nil {
		return err
	}
	if !v.NativePerms {
		return v.register(guestPath, "dir", mode, "", 0)
	}
	return nil
}

// Makedirs is like mkdir -p; silently succeeds on existing dirs.
func (v *VFS) Makedirs(guestPath string, mode int) error {
	guestPath = normPath(guestPath)
	parts := strings.Split(strings.TrimPrefix(guestPath, "/"), "/")
	cur := ""
	for _, p := range parts {
		if p == "" {
			continue
		}
		cur += "/" + p
		if !v.Exists(cur) {
			if err := v.Mkdir(cur, mode); err != nil {
				return err
			}
		}
	}
	return nil
}

// Listdir lists the entries of a guest directory.
func (v *VFS) Listdir(guestPath string) ([]string, error) {
	if !v.IsDir(guestPath) {
		return nil, newErr(20, "") // ENOTDIR
	}
	hp := v.HostPath(guestPath)
	if v.NativePerms {
		entries, err := os.ReadDir(hp)
		if err != nil {
			return []string{}, nil
		}
		var out []string
		for _, e := range entries {
			n := e.Name()
			if n == Sidecar || n == LegacySidecar || strings.HasSuffix(n, ".tmp") {
				continue
			}
			out = append(out, n)
		}
		return out, nil
	}
	data := v.reconcile(hp)
	var out []string
	for n := range data {
		if n != "." {
			out = append(out, n)
		}
	}
	return out, nil
}

// Rmdir removes an empty directory.
func (v *VFS) Rmdir(guestPath string) error {
	if !v.IsDir(guestPath) {
		return newErr(20, "")
	}
	hp := v.HostPath(guestPath)
	entries, err := v.Listdir(guestPath)
	if err != nil {
		return err
	}
	if len(entries) > 0 {
		return newErr(39, "") // ENOTEMPTY
	}
	if err := os.Remove(hp); err != nil && !os.IsNotExist(err) {
		return err
	}
	return v.unregister(guestPath)
}

// -- file operations --------------------------------------------------

// CreateFile creates an empty regular file if it doesn't already exist.
func (v *VFS) CreateFile(guestPath string, mode int) error {
	hp := v.HostPath(guestPath)
	if _, err := os.Stat(hp); os.IsNotExist(err) {
		if err := os.MkdirAll(filepath.Dir(hp), 0o755); err != nil {
			return err
		}
		f, err := os.OpenFile(hp, os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		f.Close()
	}
	if !v.NativePerms {
		return v.register(guestPath, "reg", mode, "", 0)
	}
	return nil
}

// Unlink removes a regular file (not a directory) from the VFS.
func (v *VFS) Unlink(guestPath string) error {
	meta, err := v.GetMeta(guestPath)
	if err != nil {
		return err
	}
	if meta.Type == "dir" {
		return newErr(21, "") // EISDIR
	}
	hp := v.HostPath(guestPath)
	if meta.Type == "reg" {
		if _, err := os.Stat(hp); err == nil {
			_ = os.Remove(hp)
		}
	}
	return v.unregister(guestPath)
}

var typeBits = map[string]uint32{
	"reg": syscall.S_IFREG, "dir": syscall.S_IFDIR, "lnk": syscall.S_IFLNK,
	"chr": syscall.S_IFCHR, "blk": syscall.S_IFBLK, "fifo": syscall.S_IFIFO,
}

// Stat returns file metadata in a struct analogous to Python's stat()
// dict.
func (v *VFS) Stat(guestPath string) (Stat, error) {
	hp := v.HostPath(guestPath)
	if v.NativePerms {
		st, err := os.Lstat(hp)
		if err != nil {
			return Stat{}, newErr(2, "no such file: "+guestPath)
		}
		sys, _ := st.Sys().(*syscall.Stat_t)
		if sys == nil {
			return Stat{}, newErr(5, "stat unsupported")
		}
		return Stat{
			Dev: uint64(sys.Dev), Ino: sys.Ino, Mode: sys.Mode,
			Size: sys.Size, Uid: sys.Uid, Gid: sys.Gid,
			Mtime: sys.Mtim.Sec, Atime: sys.Atim.Sec, Ctime: sys.Ctim.Sec,
			Nlink: uint64(sys.Nlink), Rdev: sys.Rdev,
		}, nil
	}
	meta, err := v.GetMeta(guestPath)
	if err != nil {
		return Stat{}, err
	}
	var size int64
	mtime := time.Now().Unix()
	if meta.Type == "reg" {
		if st, err := os.Stat(hp); err == nil {
			size = st.Size()
			mtime = st.ModTime().Unix()
		}
	} else if meta.Type == "dir" {
		size = 4096
	}
	tb, ok := typeBits[meta.Type]
	if !ok {
		tb = syscall.S_IFREG
	}
	// Stable, unique inode derived from the guest path so that dynamic
	// linkers (musl, glibc) which deduplicate shared libraries by
	// (st_dev, st_ino) don't mistake every file for the same object.
	sum := md5.Sum([]byte(normPath(guestPath)))
	var ino uint64
	for i := 0; i < 6; i++ {
		ino |= uint64(sum[i]) << (8 * i)
	}
	if ino == 0 {
		ino = 1
	}
	nlink := uint64(1)
	if meta.Type == "dir" {
		nlink = 2
	}
	return Stat{
		Dev: 1, Ino: ino,
		Mode: tb | (uint32(meta.Mode) & 0o7777),
		Size: size, Uid: uint32(meta.Uid), Gid: uint32(meta.Gid),
		Mtime: mtime, Atime: mtime, Ctime: mtime,
		Nlink: nlink, Rdev: uint64(meta.Rdev),
	}, nil
}

// Readlink returns a symlink's target.
func (v *VFS) Readlink(guestPath string) (string, error) {
	meta, err := v.GetMeta(guestPath)
	if err != nil {
		return "", err
	}
	if meta.Type != "lnk" {
		return "", newErr(22, "") // EINVAL
	}
	return meta.Target, nil
}

// Symlink registers a symlink entry (pure metadata; no real symlink is
// created on the host).
func (v *VFS) Symlink(target, guestPath string) error {
	return v.register(guestPath, "lnk", 0o777, target, 0)
}

// Mknod registers a device/special node.
func (v *VFS) Mknod(guestPath, typ string, mode, rdev int) error {
	return v.register(guestPath, typ, mode, "", rdev)
}

// -- mount table ----------------------------------------------------------

// Mount registers a mount at target.
func (v *VFS) Mount(source, target, fstype string, flags int, data string) error {
	target = normPath(target)
	fstype = strings.ToLower(fstype)
	if !v.IsDir(target) {
		if err := v.Makedirs(target, DefaultDirMode); err != nil {
			return err
		}
	}
	if fstype == "devtmpfs" {
		if err := v.EnsureDevfs(target); err != nil {
			return err
		}
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.refreshMounts()
	if source == "" {
		source = "none"
	}
	v.mounts[target] = MountInfo{Source: source, Fstype: fstype, Flags: flags, Data: data}
	return v.persistMounts()
}

// Umount removes a mount registered at target.
func (v *VFS) Umount(target string) error {
	target = normPath(target)
	v.mu.Lock()
	defer v.mu.Unlock()
	v.refreshMounts()
	if _, ok := v.mounts[target]; !ok {
		return newErr(22, "") // EINVAL: not a mountpoint we know about
	}
	delete(v.mounts, target)
	return v.persistMounts()
}

// MountType returns the fstype of the most specific mount covering
// guestPath, or "" if it's just plain host-backed storage.
func (v *VFS) MountType(guestPath string) string {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.refreshMounts()
	guestPath = normPath(guestPath)
	best, bestLen := "", -1
	for mp, info := range v.mounts {
		if guestPath == mp || strings.HasPrefix(guestPath, strings.TrimSuffix(mp, "/")+"/") {
			if len(mp) > bestLen {
				best, bestLen = info.Fstype, len(mp)
			}
		}
	}
	return best
}

// MountPointFor returns the most specific mountpoint covering
// guestPath, or "" if none.
func (v *VFS) MountPointFor(guestPath string) string {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.refreshMounts()
	guestPath = normPath(guestPath)
	best, bestLen := "", -1
	for mp := range v.mounts {
		if guestPath == mp || strings.HasPrefix(guestPath, strings.TrimSuffix(mp, "/")+"/") {
			if len(mp) > bestLen {
				best, bestLen = mp, len(mp)
			}
		}
	}
	return best
}

// MountsList returns rows for /proc/mounts. Most-recently-mounted-
// covers-earlier order isn't tracked (map iteration order isn't
// meaningful in Go either -- matches the Python note that dict
// insertion order is "close enough").
func (v *VFS) MountsList() []MountRow {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.refreshMounts()
	out := make([]MountRow, 0, len(v.mounts))
	for mp, info := range v.mounts {
		out = append(out, MountRow{Path: mp, MountInfo: info})
	}
	return out
}

// -- devtmpfs: populate the standard device nodes ------------------------
// (major, minor) pairs match the real kernel's well-known device numbers
// closely enough for guest programs that merely check "is this a char
// device" rather than caring about the exact major/minor.

type devNode struct{ major, minor int }

var devNodes = map[string]devNode{
	"null": {1, 3}, "zero": {1, 5}, "full": {1, 7},
	"random": {1, 8}, "urandom": {1, 9},
	"tty": {5, 0}, "console": {5, 1}, "ptmx": {5, 2},
}

// EnsureDevfs makes sure the standard /dev nodes exist under target.
func (v *VFS) EnsureDevfs(target string) error {
	target = strings.TrimSuffix(target, "/")
	if target == "" {
		target = "/"
	}
	if !v.IsDir(target) {
		if err := v.Makedirs(target, DefaultDirMode); err != nil {
			return err
		}
	}
	for name, dn := range devNodes {
		path := target + "/" + name
		if !v.Exists(path) {
			rdev := (dn.major << 8) | dn.minor
			if err := v.Mknod(path, "chr", 0o666, rdev); err != nil {
				return err
			}
		}
	}
	return nil
}

// Rename moves a file or directory from oldPath to newPath: the
// backing regular-file content (if any) is moved on the host, and
// the metadata entry is re-registered under the new name.
func (v *VFS) Rename(oldPath, newPath string) error {
	meta, err := v.GetMeta(oldPath)
	if err != nil {
		return err
	}
	oh, nh := v.HostPath(oldPath), v.HostPath(newPath)
	if meta.Type == "reg" {
		if _, err := os.Stat(oh); err == nil {
			if err := os.MkdirAll(filepath.Dir(nh), 0o755); err != nil {
				return err
			}
			if err := os.Rename(oh, nh); err != nil {
				return err
			}
		}
	} else if meta.Type == "dir" {
		if _, err := os.Stat(oh); err == nil {
			if err := os.MkdirAll(filepath.Dir(nh), 0o755); err != nil {
				return err
			}
			if err := os.Rename(oh, nh); err != nil {
				return err
			}
		}
	}
	if err := v.register(newPath, meta.Type, meta.Mode, meta.Target, meta.Rdev); err != nil {
		return err
	}
	return v.unregister(oldPath)
}

// Link creates a second directory entry (a hard link, best-effort --
// see the comment below) pointing at the same regular-file content as
// oldPath.
func (v *VFS) Link(oldPath, newPath string) error {
	if !v.Exists(oldPath) {
		return newErr(2, "") // ENOENT
	}
	if v.Exists(newPath) {
		return newErr(17, "") // EEXIST
	}
	meta, err := v.GetMeta(oldPath)
	if err != nil {
		return err
	}
	if meta.Type == "dir" {
		return newErr(1, "") // EPERM
	}
	if meta.Type == "reg" {
		// The sidecar-based VFS model has no notion of a true inode
		// shared by two directory entries, so a "hard link" here is a
		// content copy that starts out identical -- good enough for
		// the common case (e.g. package managers linking into place)
		// without claiming true hardlink semantics (the two entries
		// won't see each other's writes afterward).
		hostOld, hostNew := v.HostPath(oldPath), v.HostPath(newPath)
		if err := os.MkdirAll(filepath.Dir(hostNew), 0o755); err != nil {
			return err
		}
		if err := copyFile(hostOld, hostNew); err != nil {
			return err
		}
	}
	return v.register(newPath, meta.Type, meta.Mode, meta.Target, meta.Rdev)
}

// -- convenience: import a real host file/tree into the VFS -------------

// ImportHostFile copies a host file into the VFS at guestDst.
func (v *VFS) ImportHostFile(hostSrc, guestDst string, mode int) error {
	hp := v.HostPath(guestDst)
	if err := os.MkdirAll(filepath.Dir(hp), 0o755); err != nil {
		return err
	}
	if err := copyFile(hostSrc, hp); err != nil {
		return err
	}
	return v.register(guestDst, "reg", mode, "", 0)
}

// ImportHostTree recursively imports a host directory tree into the VFS.
func (v *VFS) ImportHostTree(hostSrcDir, guestDstDir string) error {
	if err := v.Makedirs(guestDstDir, DefaultDirMode); err != nil {
		return err
	}
	entries, err := os.ReadDir(hostSrcDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.Name() == Sidecar || e.Name() == LegacySidecar {
			continue
		}
		s := filepath.Join(hostSrcDir, e.Name())
		d := strings.TrimSuffix(guestDstDir, "/") + "/" + e.Name()
		if e.IsDir() {
			if err := v.ImportHostTree(s, d); err != nil {
				return err
			}
		} else {
			mode := 0o644
			if isExecutable(s) {
				mode = 0o755
			}
			if err := v.ImportHostFile(s, d, mode); err != nil {
				return err
			}
		}
	}
	return nil
}

func isExecutable(path string) bool {
	fi, err := os.Stat(path)
	if err != nil {
		return false
	}
	return fi.Mode()&0o111 != 0
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}
