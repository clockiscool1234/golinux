package procfs

import (
	"strings"
	"testing"

	"golinux/internal/fds"
	"golinux/internal/vfs"
)

type stubProc struct {
	pid      int
	argv     []string
	cwd      string
	hostname string
	boot     int64
	fdTable  *fds.Table
	vv       *vfs.VFS
}

func (s *stubProc) Pid() int         { return s.pid }
func (s *stubProc) Argv() []string   { return s.argv }
func (s *stubProc) Cwd() string      { return s.cwd }
func (s *stubProc) Hostname() string { return s.hostname }
func (s *stubProc) BootTime() int64  { return s.boot }
func (s *stubProc) Fds() *fds.Table  { return s.fdTable }
func (s *stubProc) VFS() *vfs.VFS    { return s.vv }

func newStub(t *testing.T) *stubProc {
	t.Helper()
	vv, err := vfs.New(t.TempDir(), false)
	if err != nil {
		t.Fatal(err)
	}
	return &stubProc{
		pid: 42, argv: []string{"/bin/test", "a", "b"}, cwd: "/",
		hostname: "testhost", boot: 1000, fdTable: fds.NewTable(), vv: vv,
	}
}

func TestStaticFiles(t *testing.T) {
	p := newStub(t)
	data, ok := Read("version", p)
	if !ok || !strings.Contains(string(data), "Linux version") {
		t.Fatalf("version content wrong: %q", data)
	}
	if !Exists("cpuinfo", p) {
		t.Fatal("expected cpuinfo to exist")
	}
	if !IsDir("", p) {
		t.Fatal("expected proc root to be a dir")
	}
}

func TestSelfSymlinks(t *testing.T) {
	p := newStub(t)
	if !IsSymlink("self", p) {
		t.Fatal("expected /proc/self to be a symlink")
	}
	target, ok := Readlink("self", p)
	if !ok || target != "42" {
		t.Fatalf("expected self -> 42, got %q ok=%v", target, ok)
	}
	target, ok = Readlink("self/exe", p)
	if !ok || target != "/bin/test" {
		t.Fatalf("expected self/exe -> /bin/test, got %q", target)
	}
	target, ok = Readlink("self/cwd", p)
	if !ok || target != "/" {
		t.Fatalf("expected self/cwd -> /, got %q", target)
	}
}

func TestPidStatus(t *testing.T) {
	p := newStub(t)
	data, ok := Read("self/status", p)
	if !ok {
		t.Fatal("expected self/status to exist")
	}
	if !strings.Contains(string(data), "Pid:\t42") {
		t.Fatalf("status missing pid: %q", data)
	}
	if !strings.Contains(string(data), "Name:\ttest") {
		t.Fatalf("status missing name: %q", data)
	}
}

func TestListdirRoot(t *testing.T) {
	p := newStub(t)
	names := Listdir("", p)
	found := map[string]bool{}
	for _, n := range names {
		found[n] = true
	}
	if !found["self"] || !found["mounts"] || !found["42"] {
		t.Fatalf("root listing missing expected entries: %v", names)
	}
}

func TestUnknownPathDoesNotExist(t *testing.T) {
	p := newStub(t)
	if Exists("nonexistent/nested/path", p) {
		t.Fatal("expected an unmodeled /proc path to not exist")
	}
}

func TestStatKinds(t *testing.T) {
	p := newStub(t)
	st, ok := Stat("", p)
	if !ok || st.Mode&0o170000 != 0o040000 {
		t.Fatalf("expected proc root to stat as a dir: %+v ok=%v", st, ok)
	}
	st, ok = Stat("self", p)
	if !ok || st.Mode&0o170000 != 0o120000 {
		t.Fatalf("expected self to stat as a symlink: %+v ok=%v", st, ok)
	}
	st, ok = Stat("version", p)
	if !ok || st.Mode&0o170000 != 0o100000 || st.Size == 0 {
		t.Fatalf("expected version to stat as a nonempty regular file: %+v ok=%v", st, ok)
	}
}
