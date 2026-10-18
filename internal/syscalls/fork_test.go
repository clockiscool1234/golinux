package syscalls

import (
	"encoding/binary"
	"os"
	"reflect"
	"testing"
)

func TestExecveRunsShebangInterpreter(t *testing.T) {
	proc := newMetadataTestProc(t)
	for _, dir := range []string{"/bin", "/lib", "/lib/apk", "/lib/apk/exec"} {
		if err := proc.vfs.Makedirs(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := proc.vfs.CreateFile("/bin/busybox", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := proc.vfs.CreateFile("/lib/apk/exec/trigger", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(proc.vfs.HostPath("/bin/busybox"), []byte("\x7fELF"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(proc.vfs.HostPath("/lib/apk/exec/trigger"), []byte("#!/bin/busybox sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	proc.putString(0x100, "/lib/apk/exec/trigger")
	proc.putString(0x200, "/lib/apk/exec/trigger")
	proc.putString(0x220, "/bin")
	proc.putString(0x240, "/usr/bin")
	binary.LittleEndian.PutUint64(proc.memory[0x300:], 0x200)
	binary.LittleEndian.PutUint64(proc.memory[0x308:], 0x220)
	binary.LittleEndian.PutUint64(proc.memory[0x310:], 0x240)

	result, action := sysExecve(proc, 0x100, 0x300, 0, 0, 0, 0)
	exec, ok := action.(*Execve)
	if result != 0 || !ok {
		t.Fatalf("sysExecve = %d, %T; want Execve action", result, action)
	}
	want := []string{"/bin/busybox", "sh", "/lib/apk/exec/trigger", "/bin", "/usr/bin"}
	if exec.Path != "/bin/busybox" || !reflect.DeepEqual(exec.Argv, want) {
		t.Fatalf("execve script = %q, %#v; want %q, %#v", exec.Path, exec.Argv, "/bin/busybox", want)
	}
}

func TestExecveKeepsElfArguments(t *testing.T) {
	proc := newMetadataTestProc(t)
	if err := proc.vfs.Makedirs("/bin", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := proc.vfs.CreateFile("/bin/tool", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(proc.vfs.HostPath("/bin/tool"), []byte("\x7fELF"), 0o755); err != nil {
		t.Fatal(err)
	}
	proc.putString(0x100, "/bin/tool")
	proc.putString(0x200, "/bin/tool")
	proc.putString(0x220, "arg")
	binary.LittleEndian.PutUint64(proc.memory[0x300:], 0x200)
	binary.LittleEndian.PutUint64(proc.memory[0x308:], 0x220)

	result, action := sysExecve(proc, 0x100, 0x300, 0, 0, 0, 0)
	exec, ok := action.(*Execve)
	if result != 0 || !ok {
		t.Fatalf("sysExecve = %d, %T; want Execve action", result, action)
	}
	want := []string{"/bin/tool", "arg"}
	if exec.Path != "/bin/tool" || !reflect.DeepEqual(exec.Argv, want) {
		t.Fatalf("execve ELF = %q, %#v; want %q, %#v", exec.Path, exec.Argv, "/bin/tool", want)
	}
}
