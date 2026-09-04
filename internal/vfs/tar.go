package vfs

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ExtractTar reads a tar stream from r and extracts it into the virtual
// filesystem starting at the given dest directory in the VFS. It uses the VFS's
// own metadata tracking (the .golinux_meta files) to record uid, gid, mode,
// and symlinks, so it does not require root privileges on the host OS.
func (v *VFS) ExtractTar(r io.Reader, dest string) error {
	tr := tar.NewReader(r)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			return fmt.Errorf("reading tar header: %v", err)
		}

		// Clean the path to avoid directory traversal.
		guestPath := filepath.Join(dest, "/" + strings.TrimPrefix(filepath.Clean("/"+hdr.Name), "/"))

		mode := int(hdr.FileInfo().Mode().Perm())
		uid := hdr.Uid
		gid := hdr.Gid

		// Keep track of the file type bits to set in the metadata correctly.
		// A standard stat mode includes the S_IFMT bits (e.g. 0100000 for regular file, 0040000 for dir).
		// We'll let SetMeta handle storing just the permission bits or type bits as needed,
		// but typically we'll want to translate them to the standard Linux mode bits.
		
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := v.Makedirs(guestPath, mode); err != nil {
				return fmt.Errorf("mkdir %q: %v", guestPath, err)
			}
			if err := v.SetMeta(guestPath, func(m *Meta) {
				m.Uid = uid
				m.Gid = gid
				m.Mode = mode | 040000 // S_IFDIR
			}); err != nil {
				return fmt.Errorf("set meta %q: %v", guestPath, err)
			}

		case tar.TypeReg, tar.TypeRegA:
			parent := filepath.Dir(guestPath)
			if parent != "/" {
				if err := v.Makedirs(parent, 0755); err != nil {
					return fmt.Errorf("makedirs %q: %v", parent, err)
				}
			}

			// Open the host file for writing.
			hostPath := v.HostPath(guestPath)
			f, err := os.OpenFile(hostPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
			if err != nil {
				return fmt.Errorf("create file %q: %v", guestPath, err)
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return fmt.Errorf("copy file %q: %v", guestPath, err)
			}
			f.Close()

			if err := v.SetMeta(guestPath, func(m *Meta) {
				m.Uid = uid
				m.Gid = gid
				m.Mode = mode | 0100000 // S_IFREG
			}); err != nil {
				return fmt.Errorf("set meta %q: %v", guestPath, err)
			}

		case tar.TypeSymlink:
			parent := filepath.Dir(guestPath)
			if parent != "/" {
				if err := v.Makedirs(parent, 0755); err != nil {
					return fmt.Errorf("makedirs %q: %v", parent, err)
				}
			}
			// Delete existing if necessary so Symlink doesn't fail.
			if v.Exists(guestPath) {
				v.Unlink(guestPath)
			}
			if err := v.Symlink(hdr.Linkname, guestPath); err != nil {
				return fmt.Errorf("symlink %q -> %q: %v", guestPath, hdr.Linkname, err)
			}
			if err := v.SetMeta(guestPath, func(m *Meta) {
				m.Uid = uid
				m.Gid = gid
			}); err != nil {
				return fmt.Errorf("set meta %q: %v", guestPath, err)
			}

		case tar.TypeLink: // Hard link
			parent := filepath.Dir(guestPath)
			if parent != "/" {
				if err := v.Makedirs(parent, 0755); err != nil {
					return fmt.Errorf("makedirs %q: %v", parent, err)
				}
			}
			if v.Exists(guestPath) {
				v.Unlink(guestPath)
			}
			
			// We need to resolve the linkname (which might be a relative path in the tar)
			// to an absolute guest path for our VFS. Typically tar Linknames for hardlinks
			// are absolute or relative to root.
			targetPath := "/" + strings.TrimPrefix(filepath.Clean("/"+hdr.Linkname), "/")
			
			if err := v.Link(targetPath, guestPath); err != nil {
				return fmt.Errorf("hardlink %q -> %q: %v", guestPath, targetPath, err)
			}

		case tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
			parent := filepath.Dir(guestPath)
			if parent != "/" {
				if err := v.Makedirs(parent, 0755); err != nil {
					return fmt.Errorf("makedirs %q: %v", parent, err)
				}
			}
			
			var typ string
			var s_ifmt uint32
			switch hdr.Typeflag {
			case tar.TypeChar:
				typ = "c"
				s_ifmt = 020000 // S_IFCHR
			case tar.TypeBlock:
				typ = "b"
				s_ifmt = 060000 // S_IFBLK
			case tar.TypeFifo:
				typ = "p"
				s_ifmt = 010000 // S_IFIFO
			}

			// Mknod takes (guestPath, typ string, mode, rdev int)
			// rdev is usually (major << 8) | minor, but let's just pack it how the kernel does:
			// actually Mknod splits it or takes it directly. Wait, looking at v.Mknod it takes rdev int.
			rdev := int((hdr.Devmajor << 8) | (hdr.Devminor & 0xff) | ((hdr.Devminor &^ 0xff) << 12))
			if err := v.Mknod(guestPath, typ, mode, rdev); err != nil {
				return fmt.Errorf("mknod %q: %v", guestPath, err)
			}

			if err := v.SetMeta(guestPath, func(m *Meta) {
				m.Uid = uid
				m.Gid = gid
				m.Mode = mode | int(s_ifmt)
			}); err != nil {
				return fmt.Errorf("set meta %q: %v", guestPath, err)
			}
		}
	}

	return nil
}
