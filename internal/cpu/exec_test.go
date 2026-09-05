package cpu

import "testing"

func TestMovAndArith(t *testing.T) {
	e := runUntilEnd(t, `
		mov $5, %eax
		add $3, %eax
		sub $8, %eax
	`)
	if got := reg(t, e, RegRAX); got != 0 {
		t.Fatalf("eax = %#x, want 0", got)
	}
	if !e.flag(flagZF) {
		t.Fatalf("ZF should be set after sub produced 0")
	}
}

func TestMov64Immediate(t *testing.T) {
	e := runUntilEnd(t, `
		movabs $0x1122334455667788, %rax
	`)
	if got, want := reg(t, e, RegRAX), uint64(0x1122334455667788); got != want {
		t.Fatalf("rax = %#x, want %#x", got, want)
	}
}

func TestMov32ZeroExtends(t *testing.T) {
	e := runUntilEnd(t, `
		movabs $0xFFFFFFFFFFFFFFFF, %rax
		mov $1, %eax
	`)
	if got, want := reg(t, e, RegRAX), uint64(1); got != want {
		t.Fatalf("rax = %#x, want %#x (mov to eax must zero upper 32 bits)", got, want)
	}
}

func TestAddFlags(t *testing.T) {
	// 0x7FFFFFFF + 1 signed-overflows a 32-bit add.
	e := runUntilEnd(t, `
		mov $0x7FFFFFFF, %eax
		add $1, %eax
	`)
	if got, want := reg(t, e, RegRAX), uint64(0x80000000); got != want {
		t.Fatalf("eax = %#x, want %#x", got, want)
	}
	if !e.flag(flagOF) {
		t.Fatalf("OF should be set on signed overflow")
	}
	if !e.flag(flagSF) {
		t.Fatalf("SF should be set (result has high bit set)")
	}
	if e.flag(flagCF) {
		t.Fatalf("CF should be clear (no unsigned overflow)")
	}
}

func TestSubCarry(t *testing.T) {
	e := runUntilEnd(t, `
		mov $1, %eax
		sub $2, %eax
	`)
	if got, want := reg(t, e, RegRAX), uint64(0xFFFFFFFF); got != want {
		t.Fatalf("eax = %#x, want %#x", got, want)
	}
	if !e.flag(flagCF) {
		t.Fatalf("CF should be set (unsigned borrow)")
	}
	if !e.flag(flagSF) {
		t.Fatalf("SF should be set")
	}
}

func TestIncDecPreservesCF(t *testing.T) {
	e := runUntilEnd(t, `
		mov $1, %eax
		sub $2, %eax
		inc %eax
	`)
	if !e.flag(flagCF) {
		t.Fatalf("INC must not clear CF set by the preceding SUB")
	}
}

func TestLogicOps(t *testing.T) {
	e := runUntilEnd(t, `
		mov $0xF0, %eax
		and $0x3C, %eax
		or  $0x01, %eax
		xor $0xFF, %eax
	`)
	// 0xF0 & 0x3C = 0x30; | 0x01 = 0x31; ^ 0xFF = 0xCE
	if got, want := reg(t, e, RegRAX), uint64(0xCE); got != want {
		t.Fatalf("eax = %#x, want %#x", got, want)
	}
}

func TestCmpAndConditionalJump(t *testing.T) {
	e := runUntilEnd(t, `
		mov $5, %eax
		mov $5, %ebx
		cmp %ebx, %eax
		je equal
		mov $111, %ecx
		jmp done
	equal:
		mov $222, %ecx
	done:
	`)
	if got, want := reg(t, e, RegRCX), uint64(222); got != want {
		t.Fatalf("ecx = %d, want %d (je should have been taken)", got, want)
	}
}

func TestLoop(t *testing.T) {
	// Sum 1..10 into eax using a decrementing counter in ecx.
	e := runUntilEnd(t, `
		mov $0, %eax
		mov $10, %ecx
	top:
		add %ecx, %eax
		dec %ecx
		jnz top
	`)
	if got, want := reg(t, e, RegRAX), uint64(55); got != want {
		t.Fatalf("eax = %d, want %d", got, want)
	}
	if got, want := reg(t, e, RegRCX), uint64(0); got != want {
		t.Fatalf("ecx = %d, want %d", got, want)
	}
}

func TestPushPopCallRet(t *testing.T) {
	e := runUntilEnd(t, `
		mov $10, %eax
		call addfive
		jmp done
	addfive:
		add $5, %eax
		ret
	done:
	`)
	if got, want := reg(t, e, RegRAX), uint64(15); got != want {
		t.Fatalf("eax = %d, want %d", got, want)
	}
}

func TestPushPopRegister(t *testing.T) {
	e := runUntilEnd(t, `
		mov $0x1234, %rax
		push %rax
		mov $0, %rax
		pop %rax
	`)
	if got, want := reg(t, e, RegRAX), uint64(0x1234); got != want {
		t.Fatalf("rax = %#x, want %#x", got, want)
	}
}

func TestLeaRipRelative(t *testing.T) {
	e := runUntilEnd(t, `
		lea target(%rip), %rax
	target:
		nop
	`)
	// target is the byte right after the 7-byte LEA instruction.
	want := uint64(testCodeBase + 7)
	if got := reg(t, e, RegRAX); got != want {
		t.Fatalf("rax = %#x, want %#x", got, want)
	}
}

func TestLeaSIB(t *testing.T) {
	e := runUntilEnd(t, `
		mov $0x1000, %rbx
		mov $3, %rcx
		lea 8(%rbx,%rcx,4), %rax
	`)
	want := uint64(0x1000 + 3*4 + 8)
	if got := reg(t, e, RegRAX); got != want {
		t.Fatalf("rax = %#x, want %#x", got, want)
	}
}

func TestMemoryReadWriteWithMapping(t *testing.T) {
	code := assemble(t, `
		mov $0x600000, %rbx
		movl $0xdeadbeef, (%rbx)
		mov (%rbx), %eax
	`)
	e := newTestEngine(t, code)
	if err := e.MemMap(0x600000, pageSize, ProtRead|ProtWrite); err != nil {
		t.Fatal(err)
	}
	end := testCodeBase + uint64(len(code))
	if err := e.EmuStart(testCodeBase, end); err != nil {
		t.Fatalf("EmuStart: %v", err)
	}
	if got, want := reg(t, e, RegRAX), uint64(0xdeadbeef); got != want {
		t.Fatalf("eax = %#x, want %#x", got, want)
	}
}

func TestByteRegisters(t *testing.T) {
	e := runUntilEnd(t, `
		movabs $0, %rax
		mov $0xAB, %al
		mov $0xCD, %ah
	`)
	if got, want := reg(t, e, RegRAX), uint64(0xCDAB); got != want {
		t.Fatalf("rax = %#x, want %#x", got, want)
	}
}

// TestMovzxHighByteRegisterNoRex is a regression test for a real bug
// found while implementing fork()/wait4(): with no REX prefix, a
// ModRM register-direct r/m operand encoded as 4-7 means the legacy
// %ah/%ch/%dh/%bh high-byte registers, not %spl/%bpl/%sil/%dil (that
// meaning only applies once a REX prefix -- any REX prefix, not just
// one that sets the relevant extension bit -- is present). decodeModRM
// used to hardcode "REX present" for every register-direct r/m
// operand regardless of whether the instruction actually had a REX
// prefix, so `movzbl %ah,%ecx` silently read %spl's low byte instead
// of %rax's high byte whenever no REX prefix preceded it.
//
// This isn't a hypothetical instruction pattern: it's exactly what
// glibc/musl's WEXITSTATUS() macro compiles down to right after a
// wait4() call at -O1/-O2 (`mov 0x4(%rsp),%eax; movzbl %ah,%ecx`),
// which is how this was actually found -- a forked child's real exit
// code came back mangled through a musl binary's own optimized
// WEXITSTATUS(), even though the emulator's wait4 implementation was
// writing the correct wait-status word into guest memory.
func TestMovzxHighByteRegisterNoRex(t *testing.T) {
	e := runUntilEnd(t, `
		movabs $0x2A00, %rax
		xor %ecx, %ecx
		movzbl %ah, %ecx
	`)
	if got, want := reg(t, e, RegRCX), uint64(0x2A); got != want {
		rsp := reg(t, e, RegRSP)
		t.Fatalf("movzbl %%ah,%%ecx = %#x, want %#x (bug symptom: reads %%spl = rsp&0xff = %#x instead of %%ah)", got, want, rsp&0xff)
	}
}

func TestMovzxMovsxFromMemory(t *testing.T) {
	code := assemble(t, `
		mov $0x600000, %rbx
		movb $0x80, (%rbx)
		movzbl (%rbx), %eax
		movsbl (%rbx), %ecx
	`)
	e := newTestEngine(t, code)
	if err := e.MemMap(0x600000, pageSize, ProtRead|ProtWrite); err != nil {
		t.Fatal(err)
	}
	end := testCodeBase + uint64(len(code))
	if err := e.EmuStart(testCodeBase, end); err != nil {
		t.Fatalf("EmuStart: %v", err)
	}
	if got, want := reg(t, e, RegRAX), uint64(0x80); got != want {
		t.Fatalf("movzbl: eax = %#x, want %#x", got, want)
	}
	if got, want := reg(t, e, RegRCX), uint64(0xffffff80); got != want {
		t.Fatalf("movsbl: ecx(rcx) = %#x, want %#x", got, want)
	}
}

func TestShifts(t *testing.T) {
	e := runUntilEnd(t, `
		mov $1, %eax
		shl $4, %eax
		mov $0xFF, %ebx
		shr $4, %ebx
		mov $-16, %ecx
		sar $2, %ecx
	`)
	if got, want := reg(t, e, RegRAX), uint64(0x10); got != want {
		t.Fatalf("shl: eax = %#x, want %#x", got, want)
	}
	if got, want := reg(t, e, RegRBX), uint64(0x0F); got != want {
		t.Fatalf("shr: ebx = %#x, want %#x", got, want)
	}
	if got, want := reg(t, e, RegRCX), uint64(0xfffffffc); got != want {
		t.Fatalf("sar: ecx(rcx) = %#x, want %#x", got, want)
	}
}

func TestImulTwoOperand(t *testing.T) {
	e := runUntilEnd(t, `
		mov $6, %eax
		imul $7, %eax, %eax
	`)
	if got, want := reg(t, e, RegRAX), uint64(42); got != want {
		t.Fatalf("eax = %d, want %d", got, want)
	}
}

func TestMulDiv(t *testing.T) {
	e := runUntilEnd(t, `
		mov $6, %eax
		mov $7, %ebx
		mul %ebx
		mov $100, %eax
		mov $0, %edx
		mov $9, %ebx
		div %ebx
	`)
	// mul: eax=42, edx=0 (no overflow into high half).
	// then reloaded: div 100/9 -> eax=11 (quotient), edx=1 (remainder).
	if got, want := reg(t, e, RegRAX), uint64(11); got != want {
		t.Fatalf("eax (quotient) = %d, want %d", got, want)
	}
	if got, want := reg(t, e, RegRDX), uint64(1); got != want {
		t.Fatalf("edx (remainder) = %d, want %d", got, want)
	}
}

func TestNegNot(t *testing.T) {
	e := runUntilEnd(t, `
		mov $5, %eax
		neg %eax
		mov $0x0F, %ebx
		not %ebx
	`)
	if got, want := reg(t, e, RegRAX), uint64(0xFFFFFFFB); got != want {
		t.Fatalf("neg: eax = %#x, want %#x", got, want)
	}
	if got, want := reg(t, e, RegRBX), uint64(0xFFFFFFF0); got != want {
		t.Fatalf("not: ebx = %#x, want %#x", got, want)
	}
}

func TestSetccCmovcc(t *testing.T) {
	e := runUntilEnd(t, `
		mov $5, %eax
		mov $5, %ebx
		cmp %ebx, %eax
		sete %cl
		mov $999, %edx
		mov $1, %esi
		cmove %esi, %edx
	`)
	if got, want := reg(t, e, RegRCX)&0xFF, uint64(1); got != want {
		t.Fatalf("sete: cl = %#x, want %#x", got, want)
	}
	if got, want := reg(t, e, RegRDX), uint64(1); got != want {
		t.Fatalf("cmove: edx = %d, want %d", got, want)
	}
}

func TestFSBaseTLSAccess(t *testing.T) {
	code := assemble(t, `
		mov %fs:0x10, %eax
	`)
	e := newTestEngine(t, code)
	tcb := uint64(0x700000)
	if err := e.MemMap(tcb, pageSize, ProtRead|ProtWrite); err != nil {
		t.Fatal(err)
	}
	if err := e.MemWrite(tcb+0x10, u64ToLE(0x12345678, 4)); err != nil {
		t.Fatal(err)
	}
	e.regs.fsbase = tcb
	end := testCodeBase + uint64(len(code))
	if err := e.EmuStart(testCodeBase, end); err != nil {
		t.Fatalf("EmuStart: %v", err)
	}
	if got, want := reg(t, e, RegRAX), uint64(0x12345678); got != want {
		t.Fatalf("eax = %#x, want %#x", got, want)
	}
}
