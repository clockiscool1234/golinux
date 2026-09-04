package cpu

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// assemble turns AT&T-syntax x86-64 assembly into raw machine code by
// shelling out to the host's `as`/`objcopy` (part of binutils) --
// this is a much more trustworthy source of test fixtures than
// hand-encoded byte literals, and it's exactly the same "skip
// cleanly if the tool isn't on PATH" pattern internal/emulator's own
// tests already use for musl-gcc.
func assemble(t *testing.T, asmSrc string) []byte {
	t.Helper()
	if _, err := exec.LookPath("as"); err != nil {
		t.Skip("as not available")
	}
	if _, err := exec.LookPath("objcopy"); err != nil {
		t.Skip("objcopy not available")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "t.s")
	if err := os.WriteFile(src, []byte(asmSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	obj := filepath.Join(dir, "t.o")
	cmd := exec.Command("as", "--64", "-o", obj, src)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("assembling: %v", err)
	}
	bin := filepath.Join(dir, "t.bin")
	cmd = exec.Command("objcopy", "-O", "binary", "--only-section=.text", obj, bin)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("objcopy: %v", err)
	}
	data, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

const (
	testCodeBase  = 0x400000
	testStackTop  = 0x7ffffffff000
	testStackSize = 64 * 1024
)

// newTestEngine returns an engine with `code` mapped executable at
// testCodeBase and a stack mapped ending at testStackTop, RSP already
// pointing at the top of it.
func newTestEngine(t *testing.T, code []byte) *Engine {
	t.Helper()
	e, err := NewEngine()
	if err != nil {
		t.Fatal(err)
	}
	codeSize := uint64((len(code) + pageSize - 1) &^ (pageSize - 1))
	if codeSize == 0 {
		codeSize = pageSize
	}
	if err := e.MemMap(testCodeBase, codeSize, ProtRead|ProtExec); err != nil {
		t.Fatal(err)
	}
	if err := e.MemWrite(testCodeBase, code); err != nil {
		t.Fatal(err)
	}
	if err := e.MemMap(testStackTop-testStackSize, testStackSize, ProtRead|ProtWrite); err != nil {
		t.Fatal(err)
	}
	if err := e.RegWrite(RegRSP, testStackTop-0x1000); err != nil {
		t.Fatal(err)
	}
	return e
}

// runUntilEnd assembles code, loads it, and runs it from the start to
// the very end of the mapped code region (i.e. asmSrc must not
// contain any control flow that jumps outside itself, and must not
// end mid-instruction).
func runUntilEnd(t *testing.T, asmSrc string) *Engine {
	t.Helper()
	code := assemble(t, asmSrc)
	e := newTestEngine(t, code)
	end := testCodeBase + uint64(len(code))
	if err := e.EmuStart(testCodeBase, end); err != nil {
		t.Fatalf("EmuStart: %v", err)
	}
	return e
}

func reg(t *testing.T, e *Engine, id int) uint64 {
	t.Helper()
	v, err := e.RegRead(id)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
