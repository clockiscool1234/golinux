package uc

import "testing"

// TestBasicRun writes a tiny hand-assembled x86-64 program:
//
//	mov rax, 0x2a      ; 48 c7 c0 2a 00 00 00
//	syscall            ; 0f 05   (our hook intercepts this and stops)
//
// and confirms the syscall hook fires with RAX == 0x2a, proving the
// cgo plumbing (mem map/write, reg read, insn hook, emu start/stop)
// works end to end.
func TestBasicRun(t *testing.T) {
	eng, err := NewEngine()
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	const base = 0x1000
	if err := eng.MemMap(base, 0x1000, ProtAll); err != nil {
		t.Fatal(err)
	}
	code := []byte{0x48, 0xc7, 0xc0, 0x2a, 0x00, 0x00, 0x00, 0x0f, 0x05}
	if err := eng.MemWrite(base, code); err != nil {
		t.Fatal(err)
	}

	var gotRAX uint64
	fired := false
	if err := eng.HookInsn(InsSyscall, func(e *Engine) {
		fired = true
		rax, err := e.RegRead(RegRAX)
		if err != nil {
			t.Error(err)
		}
		gotRAX = rax
		e.EmuStop()
	}); err != nil {
		t.Fatal(err)
	}

	if err := eng.EmuStart(base, 0); err != nil {
		t.Fatal(err)
	}
	if !fired {
		t.Fatal("syscall hook never fired")
	}
	if gotRAX != 0x2a {
		t.Fatalf("expected RAX=0x2a, got %#x", gotRAX)
	}
}

// TestMemUnmappedHook confirms the unmapped-memory hook fires and,
// when it returns false, EmuStart surfaces an error instead of
// hanging or silently succeeding.
func TestMemUnmappedHook(t *testing.T) {
	eng, err := NewEngine()
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()

	const base = 0x2000
	if err := eng.MemMap(base, 0x1000, ProtAll); err != nil {
		t.Fatal(err)
	}
	// mov rax, [0x999999999]  -- reads from a wildly unmapped address
	code := []byte{0x48, 0x8b, 0x04, 0x25, 0x99, 0x99, 0x99, 0x99}
	if err := eng.MemWrite(base, code); err != nil {
		t.Fatal(err)
	}

	fired := false
	if err := eng.HookMemUnmapped(func(e *Engine, memType int, addr uint64, size int) bool {
		fired = true
		return false // let it fault
	}); err != nil {
		t.Fatal(err)
	}

	err = eng.EmuStart(base, 0)
	if err == nil {
		t.Fatal("expected EmuStart to report an error for the unmapped access")
	}
	if !fired {
		t.Fatal("mem-unmapped hook never fired")
	}
}
