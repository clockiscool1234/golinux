package cpu

import (
	"encoding/binary"
	"testing"
)

func TestBlockJITControlFlowMatchesInterpreter(t *testing.T) {
	code := assemble(t, `
		mov $5, %ecx
		xor %eax, %eax
	loop:
		inc %eax
		dec %ecx
		jne loop
	`)

	results := make([]uint64, 2)
	for i, enabled := range []bool{false, true} {
		e := newTestEngine(t, code)
		e.SetBlockJIT(enabled)
		if err := e.EmuStart(testCodeBase, testCodeBase+uint64(len(code))); err != nil {
			t.Fatalf("EmuStart(jit=%v): %v", enabled, err)
		}
		results[i] = reg(t, e, RegRAX)
		if got := reg(t, e, RegRCX); got != 0 {
			t.Fatalf("jit=%v: RCX = %d; want 0", enabled, got)
		}
		if enabled {
			cached := false
			for _, block := range e.blockCache {
				if block != nil {
					cached = true
					break
				}
			}
			if !cached {
				t.Fatal("block JIT did not cache any basic blocks")
			}
		}
	}
	if results[0] != 5 || results[1] != results[0] {
		t.Fatalf("interpreter RAX=%d, block JIT RAX=%d; want both 5", results[0], results[1])
	}
}

func TestBlockJITInvalidatesSelfModifyingCode(t *testing.T) {
	code := []byte{0xb8, 1, 0, 0, 0}
	e := newTestEngine(t, code)
	e.SetBlockJIT(true)
	end := testCodeBase + uint64(len(code))
	if err := e.EmuStart(testCodeBase, end); err != nil {
		t.Fatal(err)
	}
	if got := reg(t, e, RegRAX); got != 1 {
		t.Fatalf("first run RAX = %d; want 1", got)
	}
	code[1] = 2
	if err := e.MemWrite(testCodeBase, code); err != nil {
		t.Fatal(err)
	}
	if err := e.EmuStart(testCodeBase, end); err != nil {
		t.Fatal(err)
	}
	if got := reg(t, e, RegRAX); got != 2 {
		t.Fatalf("after code write RAX = %d; want 2", got)
	}
}

func TestBlockJITLeavesSyscallsToInterpreterHook(t *testing.T) {
	code := []byte{0x0f, 0x05, 0x90}
	e := newTestEngine(t, code)
	e.SetBlockJIT(true)
	called := false
	e.HookInsn(InsSyscall, func(e *Engine) {
		called = true
		if err := e.RegWrite(RegRAX, 42); err != nil {
			t.Errorf("RegWrite in syscall hook: %v", err)
		}
	})
	if err := e.EmuStart(testCodeBase, testCodeBase+uint64(len(code))); err != nil {
		t.Fatal(err)
	}
	if !called || reg(t, e, RegRAX) != 42 {
		t.Fatalf("syscall hook called=%v RAX=%d; want true, 42", called, reg(t, e, RegRAX))
	}
}

func TestBlockJITNearConditionalBranch(t *testing.T) {
	code := []byte{0x0f, 0x85, 0x05, 0, 0, 0, 0xb8, 1, 0, 0, 0}
	for _, test := range []struct {
		name string
		zf   bool
		want uint64
	}{
		{name: "taken", zf: false, want: 0},
		{name: "not-taken", zf: true, want: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			e := newTestEngine(t, code)
			e.SetBlockJIT(true)
			e.setFlag(flagZF, test.zf)
			if err := e.EmuStart(testCodeBase, testCodeBase+uint64(len(code))); err != nil {
				t.Fatal(err)
			}
			if got := reg(t, e, RegRAX); got != test.want {
				t.Fatalf("RAX = %d; want %d", got, test.want)
			}
		})
	}
}

func TestBlockJITLongStraightLineLoopTerminates(t *testing.T) {
	code := []byte{0xb9, 3, 0, 0, 0}
	for i := 0; i < 32; i++ {
		code = append(code, 0x05, 1, 0, 0, 0)
	}
	code = append(code, 0xff, 0xc9, 0x0f, 0x85, 0, 0, 0, 0)
	binary.LittleEndian.PutUint32(code[len(code)-4:], uint32(int32(5-len(code))))
	for _, enabled := range []bool{false, true} {
		e := newTestEngine(t, code)
		e.SetBlockJIT(enabled)
		if err := e.EmuStart(testCodeBase, testCodeBase+uint64(len(code))); err != nil {
			t.Fatalf("EmuStart(jit=%v): %v", enabled, err)
		}
		if got := reg(t, e, RegRCX); got != 0 {
			t.Fatalf("jit=%v: RCX = %d; want 0", enabled, got)
		}
		if got := reg(t, e, RegRAX); got != 96 {
			t.Fatalf("jit=%v: RAX = %d; want 96", enabled, got)
		}
	}
}
