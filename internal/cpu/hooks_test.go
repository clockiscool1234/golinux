package cpu

import (
	"errors"
	"testing"
)

func TestSyscallHookAdvancesRIPAutomatically(t *testing.T) {
	code := assemble(t, `
		mov $60, %eax
		syscall
		mov $999, %ebx
	`)
	e := newTestEngine(t, code)

	var sawRAX uint64
	if err := e.HookInsn(InsSyscall, func(eng *Engine) {
		v, _ := eng.RegRead(RegRAX)
		sawRAX = v
		_ = eng.RegWrite(RegRAX, 0x42)
		// Deliberately not touching RIP: SYSCALL's contract is that
		// the engine auto-advances past it once this returns.
	}); err != nil {
		t.Fatal(err)
	}

	end := testCodeBase + uint64(len(code))
	if err := e.EmuStart(testCodeBase, end); err != nil {
		t.Fatalf("EmuStart: %v", err)
	}
	if sawRAX != 60 {
		t.Fatalf("hook saw rax=%d, want 60 (the syscall number)", sawRAX)
	}
	if got, want := reg(t, e, RegRAX), uint64(0x42); got != want {
		t.Fatalf("rax = %#x, want %#x (hook's return value)", got, want)
	}
	if got, want := reg(t, e, RegRBX), uint64(999); got != want {
		t.Fatalf("ebx = %d, want %d (instruction after syscall should have run)", got, want)
	}
}

func TestSyscallWithNoHookIsAnError(t *testing.T) {
	code := assemble(t, `
		syscall
	`)
	e := newTestEngine(t, code)
	end := testCodeBase + uint64(len(code))
	if err := e.EmuStart(testCodeBase, end); err == nil {
		t.Fatalf("expected an error running a SYSCALL with no hook installed")
	}
}

func TestCpuidHookMustAdvanceRIPItself(t *testing.T) {
	code := assemble(t, `
		cpuid
		mov $999, %ebx
	`)
	e := newTestEngine(t, code)

	if err := e.HookInsn(InsCpuid, func(eng *Engine) {
		rip, _ := eng.RegRead(RegRIP)
		_ = eng.RegWrite(RegRAX, 0x16)
		_ = eng.RegWrite(RegRIP, rip+2) // 2-byte CPUID opcode (0F A2)
	}); err != nil {
		t.Fatal(err)
	}

	end := testCodeBase + uint64(len(code))
	if err := e.EmuStart(testCodeBase, end); err != nil {
		t.Fatalf("EmuStart: %v", err)
	}
	if got, want := reg(t, e, RegRAX), uint64(0x16); got != want {
		t.Fatalf("rax = %#x, want %#x", got, want)
	}
	if got, want := reg(t, e, RegRBX), uint64(999); got != want {
		t.Fatalf("ebx = %d, want %d (instruction after cpuid should have run)", got, want)
	}
}

func TestUnmappedMemoryFaultsWithoutHook(t *testing.T) {
	code := assemble(t, `
		mov (%rax), %ebx
	`)
	e := newTestEngine(t, code)
	if err := e.RegWrite(RegRAX, 0xdead0000); err != nil {
		t.Fatal(err)
	}
	err := e.EmuStart(testCodeBase, testCodeBase+uint64(len(code)))
	if err == nil {
		t.Fatalf("expected a fault reading unmapped memory")
	}
	var fe *faultError
	if !errors.As(err, &fe) {
		t.Fatalf("expected a *faultError, got %T: %v", err, err)
	}
	if fe.MemType != MemReadUnmapped {
		t.Fatalf("MemType = %d, want MemReadUnmapped", fe.MemType)
	}
}

func TestUnmappedMemoryHookCanMapAndRetry(t *testing.T) {
	code := assemble(t, `
		mov (%rax), %ebx
	`)
	e := newTestEngine(t, code)
	target := uint64(0xdead0000)
	if err := e.RegWrite(RegRAX, target); err != nil {
		t.Fatal(err)
	}

	handled := false
	if err := e.HookMemUnmapped(func(eng *Engine, memType int, addr uint64, size int) bool {
		if handled {
			return false // avoid an infinite loop if something's wrong
		}
		handled = true
		_ = eng.MemMap(pageAddr(addr), pageSize, ProtRead|ProtWrite)
		_ = eng.MemWrite(addr, u64ToLE(0x77, 4))
		return true
	}); err != nil {
		t.Fatal(err)
	}

	end := testCodeBase + uint64(len(code))
	if err := e.EmuStart(testCodeBase, end); err != nil {
		t.Fatalf("EmuStart: %v", err)
	}
	if !handled {
		t.Fatalf("HookMemUnmapped was never called")
	}
	if got, want := reg(t, e, RegRBX), uint64(0x77); got != want {
		t.Fatalf("ebx = %#x, want %#x", got, want)
	}
}
