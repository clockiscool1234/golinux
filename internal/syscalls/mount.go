package syscalls

import (
	"strings"

	"golinux/internal/consts"
	"golinux/internal/errno"
	"golinux/internal/vfs"
)

func init() {
	register(consts.SYS_sethostname, sysSethostname)
	register(consts.SYS_setdomainname, sysSetdomainname)
	register(consts.SYS_mount, sysMount)
	register(consts.SYS_umount2, sysUmount2)
	register(consts.SYS_chroot, sysChroot)
	register(consts.SYS_pivot_root, sysPivotRoot)
}

// resolveAbs turns a (possibly relative, possibly containing "."/".."
// components) guest path into a canonical absolute one: joins it
// against the calling process's cwd if it isn't already absolute,
// then collapses "." and ".." the same way a real kernel's path walk
// would. That collapsing matters even for an already-absolute input
// like "/./proc" or a plain relative "proc" (cwd "/" makes those look
// equivalent to "/proc" to the eye, but every consumer downstream --
// especially procRel's exact-string mount-point-prefix comparison --
// needs the literal canonical string, not just "starts with a
// slash"). This must run regardless of whether the caller is about to
// follow the final component's symlink (open/stat) or deliberately
// not (lstat) -- collapsing dot-segments is a distinct concern from
// symlink resolution, and skipping it for the lstat case is exactly
// the bug that shipped once already (a real `ls ./proc` failing on
// every child entry while `ls proc`/`ls /proc` worked).
func resolveAbs(proc Proc, path string) string {
	if !strings.HasPrefix(path, "/") {
		path = strings.TrimRight(proc.Cwd(), "/") + "/" + path
	}
	return vfs.NormPath(path)
}

func sysMount(proc Proc, sourcePtr, targetPtr, fstypePtr, flags, _, _ uint64) (int64, error) {
	source, _ := cstr(proc, sourcePtr, 4096)
	target, ok := cstr(proc, targetPtr, 4096)
	if !ok || target == "" {
		return int64(-errno.EFAULT), nil
	}
	fstype, _ := cstr(proc, fstypePtr, 4096)
	full := resolveAbs(proc, target)
	if err := proc.VFS().Mount(source, full, fstype, int(flags), ""); err != nil {
		return int64(-vfsErrno(err)), nil
	}
	proc.Log("[mount] " + source + " on " + full + " type " + fstype)
	return 0, nil
}

func sysUmount2(proc Proc, targetPtr, _, _, _, _, _ uint64) (int64, error) {
	target, ok := cstr(proc, targetPtr, 4096)
	if !ok {
		return int64(-errno.EFAULT), nil
	}
	full := resolveAbs(proc, target)
	if err := proc.VFS().Umount(full); err != nil {
		return int64(-vfsErrno(err)), nil
	}
	return 0, nil
}

func rerootTo(proc Proc, pathPtr uint64) (int64, error) {
	path, ok := cstr(proc, pathPtr, 4096)
	if !ok {
		return int64(-errno.EFAULT), nil
	}
	full := resolveAbs(proc, path)
	if !proc.VFS().IsDir(full) {
		return int64(-errno.ENOTDIR), nil
	}
	newRoot, err := vfs.New(proc.VFS().HostPath(full), false)
	if err != nil {
		return int64(-errno.EIO), nil
	}
	proc.SetVFS(newRoot)
	proc.SetCwd("/")
	return 0, nil
}

func sysChroot(proc Proc, pathPtr, _, _, _, _, _ uint64) (int64, error) {
	return rerootTo(proc, pathPtr)
}

// sysPivotRoot is simplified like the Python original: there's no
// real second mount namespace to move the old root into, so this
// just switches the guest's view of "/" to new_root -- which is what
// every real-world initramfs -> switch_root flow actually cares
// about in practice.
func sysPivotRoot(proc Proc, newRootPtr, _putOldPtr, _, _, _, _ uint64) (int64, error) {
	return rerootTo(proc, newRootPtr)
}

func sysSethostname(proc Proc, namePtr, length, _, _, _, _ uint64) (int64, error) {
	data, err := proc.MemRead(namePtr, int(length))
	if err != nil {
		return int64(-errno.EFAULT), nil
	}
	proc.SetHostname(strings.TrimRight(string(data), "\x00"))
	return 0, nil
}

func sysSetdomainname(proc Proc, _, _, _, _, _, _ uint64) (int64, error) {
	return 0, nil
}
