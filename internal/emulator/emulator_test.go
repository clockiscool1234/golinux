package emulator

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golinux/internal/vfs"
)

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
