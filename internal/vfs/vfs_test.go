package vfs

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestMigratesLegacyPylinuxSidecar(t *testing.T) {
	dir := t.TempDir()
	// Simulate a vfs root created by the old "pylinux" tool: legacy
	// sidecar name, no golinux one yet.
	legacy := map[string]Meta{
		".":     {Type: "dir", Mode: DefaultDirMode},
		"hosts": {Type: "reg", Mode: 0o644},
	}
	b, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, LegacySidecar), b, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "hosts"), []byte("127.0.0.1 localhost\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	v, err := New(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	if !v.Exists("/hosts") {
		t.Fatal("expected /hosts to be visible after migration")
	}
	meta, err := v.GetMeta("/hosts")
	if err != nil {
		t.Fatal(err)
	}
	if meta.Type != "reg" || meta.Mode != 0o644 {
		t.Fatalf("migrated meta mismatch: %+v", meta)
	}

	// The legacy file should be gone, replaced by the new name.
	if _, err := os.Stat(filepath.Join(dir, LegacySidecar)); !os.IsNotExist(err) {
		t.Fatalf("expected legacy sidecar to be renamed away, stat err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, Sidecar)); err != nil {
		t.Fatalf("expected new sidecar to exist: %v", err)
	}
}

// TestNormPath is a regression test for a real bug: relative-path
// syscalls (stat, open, mkdir, etc. -- see internal/syscalls'
// resolveAbs) used to only prepend cwd without collapsing "." and
// ".." components, which happened to look right for ordinary files
// (this package's own GetMeta/Stat call normPath internally regardless)
// but broke specifically for mount points: procRel's exact-string
// comparison against the mount table needs the fully canonical form,
// not just "starts with a slash" -- found via a real `ls ./proc`
// failing on every child entry while `ls proc`/`ls /proc` worked.
func TestNormPath(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/", "/"},
		{"proc", "/proc"},
		{"/proc", "/proc"},
		{"./proc", "/proc"},
		{"/./proc", "/proc"},
		{"/proc/", "/proc"},
		{"//proc", "/proc"},
		{"/proc/cmdline", "/proc/cmdline"},
		{"./proc/cmdline", "/proc/cmdline"},
		{"/a/b/../c", "/a/c"},
		{"/a/../../b", "/b"}, // ".." past root clamps at root, doesn't escape
		{"a/./b/./c", "/a/b/c"},
	}
	for _, c := range cases {
		if got := NormPath(c.in); got != c.want {
			t.Errorf("NormPath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestBasicOps(t *testing.T) {
	dir := t.TempDir()
	v, err := New(dir, false)
	if err != nil {
		t.Fatal(err)
	}

	if err := v.Makedirs("/bin", DefaultDirMode); err != nil {
		t.Fatal(err)
	}
	if !v.IsDir("/bin") {
		t.Fatal("expected /bin to be a dir")
	}
	if err := v.CreateFile("/bin/hello", 0o755); err != nil {
		t.Fatal(err)
	}
	if !v.Exists("/bin/hello") {
		t.Fatal("expected /bin/hello to exist")
	}
	st, err := v.Stat("/bin/hello")
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode&0o7777 != 0o755 {
		t.Fatalf("mode mismatch: got %o", st.Mode&0o7777)
	}

	if err := v.Symlink("/bin/hello", "/bin/hi"); err != nil {
		t.Fatal(err)
	}
	target, err := v.Readlink("/bin/hi")
	if err != nil {
		t.Fatal(err)
	}
	if target != "/bin/hello" {
		t.Fatalf("symlink target mismatch: %q", target)
	}

	if err := v.EnsureDevfs("/dev"); err != nil {
		t.Fatal(err)
	}
	if !v.Exists("/dev/null") {
		t.Fatal("expected /dev/null to exist after EnsureDevfs")
	}
	nullMeta, err := v.GetMeta("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	if nullMeta.Type != "chr" || nullMeta.Rdev != (1<<8|3) {
		t.Fatalf("unexpected /dev/null meta: %+v", nullMeta)
	}

	if err := v.Mount("proc", "/proc", "proc", 0, ""); err != nil {
		t.Fatal(err)
	}
	if got := v.MountType("/proc/self/status"); got != "proc" {
		t.Fatalf("MountType mismatch: %q", got)
	}
	if got := v.MountType("/bin/hello"); got != "" {
		t.Fatalf("expected no mount for /bin/hello, got %q", got)
	}

	entries, err := v.Listdir("/bin")
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, e := range entries {
		found[e] = true
	}
	if !found["hello"] || !found["hi"] {
		t.Fatalf("listdir missing entries: %v", entries)
	}

	if err := v.Unlink("/bin/hi"); err != nil {
		t.Fatal(err)
	}
	if v.Exists("/bin/hi") {
		t.Fatal("expected /bin/hi to be gone")
	}
}

func TestReadsRealPythonSidecars(t *testing.T) {
	// This validates wire-format compatibility with the existing
	// alpinevfs tree produced by the Python implementation: same
	// JSON sidecar layout, same semantics.
	root := "/tmp/testvfs_copy"
	if _, err := os.Stat(root); err != nil {
		t.Skip("no real alpinevfs copy available at", root)
	}
	v, err := New(root, false)
	if err != nil {
		t.Fatal(err)
	}

	if !v.IsDir("/etc") {
		t.Fatal("/etc should be a dir")
	}
	if !v.Exists("/etc/hosts") {
		t.Fatal("/etc/hosts should exist")
	}
	meta, err := v.GetMeta("/etc/hosts")
	if err != nil {
		t.Fatal(err)
	}
	if meta.Type != "reg" {
		t.Fatalf("expected reg, got %s", meta.Type)
	}
	st, err := v.Stat("/etc/hosts")
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.Stat(filepath.Join(root, "etc", "hosts"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Size != want.Size() {
		t.Fatalf("size mismatch: vfs=%d disk=%d", st.Size, want.Size())
	}

	entries, err := v.Listdir("/etc")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 5 {
		t.Fatalf("expected many /etc entries, got %d", len(entries))
	}
}
