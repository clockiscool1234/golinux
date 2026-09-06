package emulator

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golinux/internal/vfs"
)

// TestStatRelativeToMountPoint is an end-to-end regression test for a
// real bug: a program's plain stat("proc", ...) / stat("./proc", ...)
// against a mounted `-t proc` mountpoint reported ENOENT, while
// stat("/proc", ...) (absolute) worked fine -- because sysStat/
// sysLstat (and a dozen sibling legacy path syscalls) never resolved
// a relative path against the process's cwd before reaching procRel's
// mount-table comparison, and even once that was fixed, "./proc"
// specifically still broke because collapsing "." segments was only
// happening as an accidental side effect of the *symlink-following*
// step -- which lstat correctly skips, since it must not follow the
// final component. Found via a real `ls ./proc` failing on every
// child entry while `ls proc`/`ls /proc` worked. Exit code 0 from the
// child program below means every stat/access attempt succeeded (see
// the C source for exactly what it checks and how it reports which
// check failed).
func TestStatRelativeToMountPoint(t *testing.T) {
	if _, err := exec.LookPath("musl-gcc"); err != nil {
		t.Skip("musl-gcc not available")
	}

	dir := t.TempDir()
	src := filepath.Join(dir, "statrel.c")
	if err := os.WriteFile(src, []byte(statRelC), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "statrel")
	cmd := exec.Command("musl-gcc", "-static", "-no-pie", "-O2", "-o", bin, src)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("compiling test binary: %v", err)
	}

	vfsRoot := filepath.Join(dir, "vfsroot")
	vv, err := vfs.New(vfsRoot, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := vv.ImportHostFile(bin, "/bin/statrel", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := vv.Mount("proc", "/proc", "proc", 0, ""); err != nil {
		t.Fatal(err)
	}

	proc, err := NewProcess(vv, []string{"/bin/statrel"}, nil, "/", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := proc.Load(vv.HostPath("/bin/statrel")); err != nil {
		t.Fatal(err)
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	origStdout := os.Stdout
	os.Stdout = w
	code, runErr := proc.Run()
	os.Stdout = origStdout
	w.Close()
	var out bytes.Buffer
	out.ReadFrom(r)

	if runErr != nil {
		t.Fatalf("Run: %v", runErr)
	}
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; output: %s", code, out.String())
	}
}

const statRelC = `#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

// lstat, not stat: this is what a real "ls" uses per directory entry
// (it must not follow the final component's symlink), and it's
// exactly the case that stayed broken longer than plain stat() --
// stat()'s symlink-following step happened to collapse "./"
// internally as a side effect, masking the bug for anything that
// follows symlinks; lstat() correctly skips that step, which is
// exactly why it needs its own explicit dot-collapsing rather than
// getting it for free.
static int check(const char *label, const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) {
        printf("FAIL: lstat(\"%s\") failed: %s\n", path, label);
        return 1;
    }
    if (!S_ISDIR(st.st_mode)) {
        printf("FAIL: lstat(\"%s\") not a directory: %s\n", path, label);
        return 1;
    }
    return 0;
}

static int checkExists(const char *label, const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) {
        printf("FAIL: lstat(\"%s\") failed: %s\n", path, label);
        return 1;
    }
    return 0;
}

int main(void) {
    int failures = 0;
    failures += check("bare relative", "proc");
    failures += check("absolute", "/proc");
    failures += check("dot-relative", "./proc");
    failures += checkExists("nested dot-relative", "./proc/version");
    return failures ? 1 : 0;
}
`

// TestIoctlNotATtyOnRegularFile is a regression test for ioctl(2)
// having no handler at all before this: every request, for every fd,
// fell through the generic "unimplemented syscall" path and returned
// ENOSYS unconditionally. That's a bigger problem than it looks --
// isatty(fd) in musl (and glibc) is implemented as exactly one thing,
// "does ioctl(fd, TCGETS, &buf) succeed?" -- so with ioctl() always
// failing, isatty() always returned false for every guest program, on
// every fd, even a real terminal. The practical, user-visible symptom
// that surfaced this: an interactive ash session never printed its
// "/ # " prompt, because ash checks isatty(0) before deciding whether
// to print one.
//
// This test covers the deterministic, non-terminal-dependent half of
// the fix: a terminal ioctl against an ordinary regular file must
// report ENOTTY (not ENOSYS, not success) -- exactly what a real
// kernel says for the same request against the same kind of fd. The
// positive case (a real terminal succeeding) needs an actual PTY to
// verify and isn't practical to assert deterministically in a unit
// test; it was confirmed separately end-to-end (a real ash session
// under a PTY started printing its prompt after this fix).
func TestIoctlNotATtyOnRegularFile(t *testing.T) {
	if _, err := exec.LookPath("musl-gcc"); err != nil {
		t.Skip("musl-gcc not available")
	}

	dir := t.TempDir()
	src := filepath.Join(dir, "ioctltest.c")
	if err := os.WriteFile(src, []byte(ioctlTestC), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "ioctltest")
	cmd := exec.Command("musl-gcc", "-static", "-no-pie", "-O2", "-o", bin, src)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("compiling test binary: %v", err)
	}

	vfsRoot := filepath.Join(dir, "vfsroot")
	vv, err := vfs.New(vfsRoot, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := vv.ImportHostFile(bin, "/bin/ioctltest", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := vv.CreateFile("/regular", 0o644); err != nil {
		t.Fatal(err)
	}

	proc, err := NewProcess(vv, []string{"/bin/ioctltest"}, nil, "/", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := proc.Load(vv.HostPath("/bin/ioctltest")); err != nil {
		t.Fatal(err)
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	origStdout := os.Stdout
	os.Stdout = w
	code, runErr := proc.Run()
	os.Stdout = origStdout
	w.Close()
	var out bytes.Buffer
	out.ReadFrom(r)

	if runErr != nil {
		t.Fatalf("Run: %v", runErr)
	}
	if code != 0 {
		t.Fatalf("exit code = %d, want 0; output: %s", code, out.String())
	}
}

const ioctlTestC = `#include <stdio.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

int main(void) {
    int fd = open("/regular", O_RDONLY);
    if (fd < 0) {
        printf("FAIL: open(/regular) failed\n");
        return 1;
    }
    struct termios t;
    if (ioctl(fd, TCGETS, &t) == 0) {
        printf("FAIL: TCGETS on a regular file unexpectedly succeeded\n");
        return 1;
    }
    if (errno != ENOTTY) {
        printf("FAIL: TCGETS on a regular file: errno=%d, want ENOTTY(%d)\n", errno, ENOTTY);
        return 1;
    }
    return 0;
}
`

// TestRunHelloWorld builds examples/hello.c as a static musl binary
// and runs it end to end through Process.Load/Run, capturing real
// stdout via a redirected os.Stdout -- this exercises ELF loading,
// stack/auxv setup, the Unicorn hooks, and the syscalls package all
// together against real machine code.
func TestRunHelloWorld(t *testing.T) {
	if _, err := exec.LookPath("musl-gcc"); err != nil {
		t.Skip("musl-gcc not available")
	}

	dir := t.TempDir()
	src := filepath.Join(dir, "hello.c")
	if err := os.WriteFile(src, []byte(helloC), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "hello")
	cmd := exec.Command("musl-gcc", "-static", "-no-pie", "-O2", "-o", bin, src)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("compiling test binary: %v", err)
	}

	vfsRoot := filepath.Join(dir, "vfsroot")
	vv, err := vfs.New(vfsRoot, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := vv.ImportHostFile(bin, "/bin/hello", 0o755); err != nil {
		t.Fatal(err)
	}

	proc, err := NewProcess(vv, []string{"/bin/hello", "arg1", "arg2"}, nil, "/", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := proc.Load(vv.HostPath("/bin/hello")); err != nil {
		t.Fatal(err)
	}

	// Capture what the guest's write()/writev() syscalls send to fd 1
	// by swapping os.Stdout for a pipe for the duration of Run().
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	origStdout := os.Stdout
	os.Stdout = w
	code, runErr := proc.Run()
	os.Stdout = origStdout
	w.Close()
	if runErr != nil {
		t.Fatal(runErr)
	}
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	var buf bytes.Buffer
	buf.ReadFrom(r)
	got := buf.String()
	want := "Hello, world! argc=3\n  argv[0] = /bin/hello\n  argv[1] = arg1\n  argv[2] = arg2\n"
	if got != want {
		t.Fatalf("output mismatch:\n got:  %q\n want: %q", got, want)
	}
}

const helloC = `#include <stdio.h>

int main(int argc, char **argv) {
    printf("Hello, world! argc=%d\n", argc);
    for (int i = 0; i < argc; i++) {
        printf("  argv[%d] = %s\n", i, argv[i]);
    }
    return 0;
}
`
