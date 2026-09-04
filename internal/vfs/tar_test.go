package vfs

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestExtractTar(t *testing.T) {
	tmp := t.TempDir()
	vv, err := New(tmp, false)
	if err != nil {
		t.Fatalf("New VFS: %v", err)
	}

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	// 1. Create a directory
	dirHdr := &tar.Header{
		Name:     "etc",
		Typeflag: tar.TypeDir,
		Mode:     0755,
		Uid:      1000,
		Gid:      1000,
	}
	if err := tw.WriteHeader(dirHdr); err != nil {
		t.Fatal(err)
	}

	// 2. Create a regular file
	fileHdr := &tar.Header{
		Name:     "etc/passwd",
		Typeflag: tar.TypeReg,
		Mode:     0644,
		Uid:      0,
		Gid:      0,
		Size:     12,
	}
	if err := tw.WriteHeader(fileHdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("hello passwd")); err != nil {
		t.Fatal(err)
	}

	// 3. Create a symlink
	symHdr := &tar.Header{
		Name:     "bin/sh",
		Typeflag: tar.TypeSymlink,
		Linkname: "bash",
		Uid:      0,
		Gid:      0,
	}
	if err := tw.WriteHeader(symHdr); err != nil {
		t.Fatal(err)
	}

	// 4. Create a hardlink
	hardHdr := &tar.Header{
		Name:     "etc/passwd_hard",
		Typeflag: tar.TypeLink,
		Linkname: "etc/passwd",
		Uid:      0,
		Gid:      0,
	}
	if err := tw.WriteHeader(hardHdr); err != nil {
		t.Fatal(err)
	}

	// 5. Create a character device
	devHdr := &tar.Header{
		Name:     "dev/null",
		Typeflag: tar.TypeChar,
		Mode:     0666,
		Devmajor: 1,
		Devminor: 3,
	}
	if err := tw.WriteHeader(devHdr); err != nil {
		t.Fatal(err)
	}

	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	// Extract into VFS at root "/"
	if err := vv.ExtractTar(&buf, "/"); err != nil {
		t.Fatalf("ExtractTar: %v", err)
	}

	// Verify directory
	meta, err := vv.GetMeta("/etc")
	if err != nil {
		t.Errorf("/etc missing: %v", err)
	}
	if meta.Uid != 1000 || meta.Gid != 1000 || (meta.Mode&0777) != 0755 {
		t.Errorf("/etc meta mismatch: %+v", meta)
	}

	// Verify file
	meta, err = vv.GetMeta("/etc/passwd")
	if err != nil {
		t.Errorf("/etc/passwd missing: %v", err)
	}
	if meta.Uid != 0 || meta.Gid != 0 || (meta.Mode&0777) != 0644 {
		t.Errorf("/etc/passwd meta mismatch: %+v", meta)
	}
	content, err := os.ReadFile(filepath.Join(tmp, "etc/passwd"))
	if err != nil {
		t.Errorf("read host file /etc/passwd: %v", err)
	}
	if string(content) != "hello passwd" {
		t.Errorf("file content = %q, want 'hello passwd'", content)
	}

	// Verify symlink
	meta, err = vv.GetMeta("/bin/sh")
	if err != nil {
		t.Errorf("/bin/sh missing: %v", err)
	}
	target, err := vv.Readlink("/bin/sh")
	if err != nil {
		t.Errorf("readlink /bin/sh: %v", err)
	}
	if target != "bash" {
		t.Errorf("symlink target = %q, want 'bash'", target)
	}

	// Verify hardlink
	meta, err = vv.GetMeta("/etc/passwd_hard")
	if err != nil {
		t.Errorf("/etc/passwd_hard missing: %v", err)
	}
	content, err = os.ReadFile(filepath.Join(tmp, "etc/passwd_hard"))
	if err != nil {
		t.Errorf("read host file /etc/passwd_hard: %v", err)
	}
	if string(content) != "hello passwd" {
		t.Errorf("hardlink file content = %q, want 'hello passwd'", content)
	}

	// Verify character device
	meta, err = vv.GetMeta("/dev/null")
	if err != nil {
		t.Errorf("/dev/null missing: %v", err)
	}
	if meta.Mode&020000 == 0 { // S_IFCHR
		t.Errorf("/dev/null is not a char device: %o", meta.Mode)
	}
}
