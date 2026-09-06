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

// TestXadd is a regression test for a real crash: the *next* opcode a
// dynamically-linked Alpine busybox/apk binary hit, right after
// fixing the PREFETCHh gap above -- "unsupported two-byte opcode 0F
// 0xc1" -- coming from ld-musl's own startup code (likely a lock-free
// refcount/increment, XADD's classic use, gated behind a LOCK prefix
// that's irrelevant to us -- see the case's comment in twobyte.go).
// Covers both the 32-bit and 8-bit forms (0F C1 and 0F C0), and
// checks both halves of XADD's swap-then-add semantics: the register
// operand ends up with the destination's *original* value, and the
// destination ends up with the sum.
func TestXadd(t *testing.T) {
	e := runUntilEnd(t, `
		mov $100, %eax
		mov $7, %ecx
		xadd %ecx, %eax
		mov $0x12, %dl
		mov $0x03, %bl
		xadd %bl, %dl
	`)
	if got, want := reg(t, e, RegRAX), uint64(107); got != want {
		t.Fatalf("xadd dest (eax) = %d, want %d", got, want)
	}
	if got, want := reg(t, e, RegRCX), uint64(100); got != want {
		t.Fatalf("xadd src (ecx) = %d, want %d (should hold dest's original value)", got, want)
	}
	if got, want := reg(t, e, RegRDX)&0xff, uint64(0x15); got != want {
		t.Fatalf("xadd byte-form dest (dl) = %#x, want %#x", got, want)
	}
	if got, want := reg(t, e, RegRBX)&0xff, uint64(0x12); got != want {
		t.Fatalf("xadd byte-form src (bl) = %#x, want %#x", got, want)
	}
}

// TestBswap is a regression test for a real crash hit right after
// fixing XADD above: a genuine Alpine apk-tools binary (whose SHA256
// implementation uses BSWAP to convert the digest's endianness) hit
// "unsupported two-byte opcode 0F 0xc8". Covers both the 32-bit form
// (no REX.W) and the 64-bit form (REX.W), and both the plain and
// REX.B-extended register-in-opcode encodings.
func TestBswap(t *testing.T) {
	e := runUntilEnd(t, `
		mov $0x11223344, %eax
		bswap %eax
		movabs $0x1122334455667788, %rbx
		bswap %rbx
		mov $0xAABBCCDD, %r9d
		bswap %r9d
	`)
	if got, want := reg(t, e, RegRAX), uint64(0x44332211); got != want {
		t.Fatalf("bswap %%eax = %#x, want %#x", got, want)
	}
	if got, want := reg(t, e, RegRBX), uint64(0x8877665544332211); got != want {
		t.Fatalf("bswap %%rbx = %#x, want %#x", got, want)
	}
	if got, want := reg(t, e, RegR9), uint64(0xDDCCBBAA); got != want {
		t.Fatalf("bswap %%r9d (REX.B-extended) = %#x, want %#x", got, want)
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

// TestPrefetchAndFenceHintsAreNops is a regression test for the
// actual bug report: a real Alpine busybox/ash binary crashed with
// "unsupported two-byte opcode 0F 0x18" the first time fork() +
// dynamic-linking code ran far enough to execute a PREFETCHh
// instruction (previously unreachable, since fork() always failed
// with ENOSYS before this port implemented it -- see fork.go). This
// covers that whole family (0F 0D, 0F 18-1D/1F, and LFENCE/MFENCE/
// SFENCE in the 0F AE group): all pure cache/ordering hints with zero
// architectural effect for this emulator. PREFETCHh in particular
// must not fault even on a garbage address -- real hardware doesn't
// either -- so this also exercises that against an address nowhere
// near anything mapped.
func TestPrefetchAndFenceHintsAreNops(t *testing.T) {
	e := runUntilEnd(t, `
		mov $0x600000, %rax
		mov $0x2A, %ecx
		prefetcht0 (%rax)
		prefetcht1 (%rax)
		prefetcht2 (%rax)
		prefetchnta (%rax)
		prefetchw (%rax)
		lfence
		mfence
		sfence
		mov $0x7fffffffffff, %rdx
		prefetcht0 (%rdx)
	`)
	if got, want := reg(t, e, RegRCX), uint64(0x2A); got != want {
		t.Fatalf("hint instructions clobbered ecx: got %#x, want %#x", got, want)
	}
}

func TestMovntps(t *testing.T) {
	code := assemble(t, `
		mov $0x600000, %rax
		movntps %xmm1, (%rax)
	`)
	e := newTestEngine(t, code)
	if err := e.MemMap(0x600000, pageSize, ProtRead|ProtWrite); err != nil {
		t.Fatal(err)
	}
	wantLo, wantHi := uint64(0x1122334455667788), uint64(0x99AABBCCDDEEFF00)
	if err := e.RegWriteXMM(1, wantLo, wantHi); err != nil {
		t.Fatal(err)
	}
	end := testCodeBase + uint64(len(code))
	if err := e.EmuStart(testCodeBase, end); err != nil {
		t.Fatalf("EmuStart: %v", err)
	}
	buf, err := e.MemRead(0x600000, 16)
	if err != nil {
		t.Fatal(err)
	}
	gotLo, gotHi := leToU64(buf[:8]), leToU64(buf[8:])
	if gotLo != wantLo || gotHi != wantHi {
		t.Fatalf("memory = %#x %#x, want %#x %#x", gotLo, gotHi, wantLo, wantHi)
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
