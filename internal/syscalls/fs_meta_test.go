package syscalls

import (
	"errors"
	"testing"

	"golinux/internal/consts"
	"golinux/internal/errno"
	"golinux/internal/vfs"
)

type metadataTestProc struct {
	Proc
	memory []byte
	vfs    *vfs.VFS
}

func (p *metadataTestProc) MemRead(addr uint64, size int) ([]byte, error) {
	if size < 0 || addr > uint64(len(p.memory)) || uint64(size) > uint64(len(p.memory))-addr {
		return nil, errors.New("invalid guest memory read")
	}
	return append([]byte(nil), p.memory[int(addr):int(addr)+size]...), nil
}

func (p *metadataTestProc) MemWrite(addr uint64, data []byte) error {
	if addr > uint64(len(p.memory)) || uint64(len(data)) > uint64(len(p.memory))-addr {
		return errors.New("invalid guest memory write")
	}
	copy(p.memory[int(addr):], data)
	return nil
}

func (p *metadataTestProc) VFS() *vfs.VFS { return p.vfs }
func (p *metadataTestProc) Cwd() string   { return "/" }

func newMetadataTestProc(t *testing.T) *metadataTestProc {
	t.Helper()
	vv, err := vfs.New(t.TempDir(), false)
	if err != nil {
		t.Fatal(err)
	}
	return &metadataTestProc{memory: make([]byte, 8192), vfs: vv}
}

func (p *metadataTestProc) putString(addr uint64, value string) {
	copy(p.memory[int(addr):], append([]byte(value), 0))
}

func atFDCWDArg() uint64 {
	dirfd := int64(consts.AT_FDCWD)
	return uint64(dirfd)
}

func TestFchownatPreservesUnspecifiedIDsAndHonorsNoFollow(t *testing.T) {
	proc := newMetadataTestProc(t)
	if err := proc.vfs.CreateFile("/owned", 0o644); err != nil {
		t.Fatal(err)
	}
	if err := proc.vfs.SetMeta("/owned", func(m *vfs.Meta) { m.Uid, m.Gid = 12, 34 }); err != nil {
		t.Fatal(err)
	}
	if err := proc.vfs.Symlink("/owned", "/link"); err != nil {
		t.Fatal(err)
	}
	if err := proc.vfs.SetMeta("/link", func(m *vfs.Meta) { m.Uid, m.Gid = 56, 78 }); err != nil {
		t.Fatal(err)
	}
	proc.putString(0x100, "/link")

	result, err := Dispatch(proc, consts.SYS_fchownat, atFDCWDArg(), 0x100, 90, uint64(^uint32(0)), consts.AT_SYMLINK_NOFOLLOW, 0)
	if err != nil || result != 0 {
		t.Fatalf("fchownat = %d, %v; want 0, nil", result, err)
	}

	linkMeta, err := proc.vfs.GetMeta("/link")
	if err != nil {
		t.Fatal(err)
	}
	if linkMeta.Uid != 90 || linkMeta.Gid != 78 {
		t.Fatalf("symlink owner = %d:%d; want 90:78", linkMeta.Uid, linkMeta.Gid)
	}
	targetMeta, err := proc.vfs.GetMeta("/owned")
	if err != nil {
		t.Fatal(err)
	}
	if targetMeta.Uid != 12 || targetMeta.Gid != 34 {
		t.Fatalf("target owner changed to %d:%d; want 12:34", targetMeta.Uid, targetMeta.Gid)
	}
}

func TestFchownatRequiresNonemptyPathWithoutEmptyPathFlag(t *testing.T) {
	proc := newMetadataTestProc(t)
	proc.putString(0x100, "")

	result, err := Dispatch(proc, consts.SYS_fchownat, atFDCWDArg(), 0x100, 1, 2, 0, 0)
	if err != nil || result != int64(-errno.ENOENT) {
		t.Fatalf("fchownat(empty path) = %d, %v; want -ENOENT, nil", result, err)
	}
}

func TestSymlinkatCreatesGuestSymlink(t *testing.T) {
	proc := newMetadataTestProc(t)
	proc.putString(0x100, "libexample.so.1")
	proc.putString(0x200, "/libexample.so")
	result, err := Dispatch(proc, consts.SYS_symlinkat, 0, atFDCWDArg(), 0x200, 0, 0, 0)
	if err != nil || result != int64(-errno.EFAULT) {
		t.Fatalf("symlinkat(null target) = %d, %v; want -EFAULT, nil", result, err)
	}

	result, err = Dispatch(proc, consts.SYS_symlinkat, 0x100, atFDCWDArg(), 0x200, 0, 0, 0)
	if err != nil || result != 0 {
		t.Fatalf("symlinkat = %d, %v; want 0, nil", result, err)
	}
	meta, err := proc.vfs.GetMeta("/libexample.so")
	if err != nil {
		t.Fatal(err)
	}
	if meta.Type != "lnk" || meta.Target != "libexample.so.1" {
		t.Fatalf("symlink metadata = %#v; want target libexample.so.1", meta)
	}
}
