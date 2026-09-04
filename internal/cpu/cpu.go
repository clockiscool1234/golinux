// Package cpu is a native, pure-Go x86-64 CPU emulator: no cgo, no
// libunicorn, no C toolchain required to build or run it.
//
// It exists to eventually replace internal/uc as the backend behind
// internal/emulator, per the "Future direction" note in the top-level
// README. To make that swap a small, mechanical change rather than a
// rewrite of internal/emulator, Engine deliberately mirrors the exact
// method surface of uc.Engine: MemMap/MemUnmap/MemProtect/MemRead/
// MemWrite, RegRead/RegWrite, HookInsn/HookMemUnmapped, EmuStart/
// EmuStop/Close, and the same Reg*/Ins*/Prot*/Mem*Unmapped constant
// names (with package-local values -- internal/emulator would just
// need `uc.RegRAX` etc. changed to `cpu.RegRAX` etc., and the `engine
// *uc.Engine` field's type changed).
//
// Scope of this first pass: general-purpose integer execution only.
//
//	Implemented:
//	  - Paged virtual memory with map/unmap/protect and permission
//	    enforcement on the fetch/decode/execute path (internal/uc's
//	    HookMemUnmapped equivalent).
//	  - All 16 GPRs, RIP, RFLAGS, FS_BASE/GS_BASE, at 8/16/32/64-bit
//	    widths (including the legacy AH/CH/DH/BH high-byte encoding
//	    when no REX prefix is present).
//	  - REX and legacy prefixes 0x66 (operand size), 0x64/0x65
//	    (FS/GS segment override -- FS is what musl/glibc TLS actually
//	    needs, since arch_prctl(ARCH_SET_FS) points it at the TCB).
//	  - Data movement: MOV (all encodings), MOVZX/MOVSX/MOVSXD, LEA
//	    (incl. RIP-relative), PUSH/POP, XCHG, CDQE/CWDE/CBW, CQO/CDQ/
//	    CWD, LEAVE, SETcc, CMOVcc, NOP (incl. multi-byte 0F 1F and
//	    ENDBR64, which decode as NOP -- CET is not modeled).
//	  - Arithmetic/logic: ADD/OR/ADC/SBB/AND/SUB/XOR/CMP in all their
//	    register/memory/immediate encodings, TEST, INC/DEC, NOT/NEG,
//	    MUL/IMUL/DIV/IDIV, SHL/SHR/SAR/ROL/ROR, IMUL (2- and
//	    3-operand forms), with EFLAGS (CF/PF/AF/ZF/SF/OF) computed to
//	    match real hardware for every op above.
//	  - Control flow: JMP/CALL (relative and indirect through r/m),
//	    RET (with and without an immediate stack-adjust), Jcc (short
//	    and near), and SYSCALL/CPUID as trap instructions dispatched
//	    through HookInsn, exactly like uc.Engine's InsSyscall/InsCpuid
//	    hooks -- see the doc comment on HookInsn for the (deliberately
//	    quirky, Unicorn-matching) RIP-advance behavior of each.
//	  - String instructions: MOVS/STOS/LODS/CMPS/SCAS at every width,
//	    with REP/REPE/REPNE prefixes (each rep executes the whole
//	    count in one Go loop inside a single decoded instruction,
//	    rather than being individually re-enterable/interruptible the
//	    way real hardware's microcode is -- indistinguishable from the
//	    outside for a single-threaded interpreter like this one), and
//	    CLD/STD for the direction flag they honor.
//
//	Not implemented yet (each is a real, separable follow-up):
//	  - SSE/AVX, x87 floating point, MMX.
//	  - Far jumps/calls, IN/OUT, most of the 0F-prefixed instruction
//	    space beyond what's listed above (BT/BSF/BSR/POPCNT/...).
//	  - Address-size override (0x67) -- 64-bit addressing only.
//	  - Precise AF (auxiliary carry) semantics for every corner case;
//	    it's computed with the standard nibble-carry formula, which
//	    is exactly right for ADD/SUB and a reasonable approximation
//	    elsewhere. Nothing in a normal compiled C program reads AF
//	    (it exists for decimal-adjust instructions, which aren't
//	    implemented), so this has never mattered in practice.
//
// An unsupported opcode is a decode error, not a silent miscompile:
// EmuStart returns it, the same way an unmapped-memory access does
// when no hook (or a hook returning false) handles it.
package cpu

import "fmt"

// Register IDs. Values 0-15 are chosen to equal the raw x86 register
// encoding (the 4-bit index formed by REX.R/X/B + the 3-bit field in
// an opcode or ModRM byte) so decode can index straight into the GPR
// array with no translation table.
const (
	RegRAX = iota
	RegRCX
	RegRDX
	RegRBX
	RegRSP
	RegRBP
	RegRSI
	RegRDI
	RegR8
	RegR9
	RegR10
	RegR11
	RegR12
	RegR13
	RegR14
	RegR15
	RegRIP
	RegEFLAGS
	RegFSBASE
	RegGSBASE
)

// XMM/YMM register IDs for RegReadXMM / RegWriteXMM etc.
// These do not overlap the GPR/RIP/FLAGS IDs above (those are 0-19).
const (
	RegXMM0  = 100
	RegXMM1  = 101
	RegXMM2  = 102
	RegXMM3  = 103
	RegXMM4  = 104
	RegXMM5  = 105
	RegXMM6  = 106
	RegXMM7  = 107
	RegXMM8  = 108
	RegXMM9  = 109
	RegXMM10 = 110
	RegXMM11 = 111
	RegXMM12 = 112
	RegXMM13 = 113
	RegXMM14 = 114
	RegXMM15 = 115

	RegYMM0  = 116
	RegYMM1  = 117
	RegYMM2  = 118
	RegYMM3  = 119
	RegYMM4  = 120
	RegYMM5  = 121
	RegYMM6  = 122
	RegYMM7  = 123
	RegYMM8  = 124
	RegYMM9  = 125
	RegYMM10 = 126
	RegYMM11 = 127
	RegYMM12 = 128
	RegYMM13 = 129
	RegYMM14 = 130
	RegYMM15 = 131

	// RegMXCSR is the SSE control/status register.
	RegMXCSR = 132
)

// Instruction IDs usable with HookInsn.
const (
	InsSyscall = iota
	InsCpuid
)

// Memory protection bits for MemMap/MemProtect.
const (
	ProtNone  = 0
	ProtRead  = 1 << 0
	ProtWrite = 1 << 1
	ProtExec  = 1 << 2
	ProtAll   = ProtRead | ProtWrite | ProtExec
)

// MemType values passed to the MemUnmapped hook.
const (
	MemReadUnmapped = iota
	MemWriteUnmapped
	MemFetchUnmapped
)

// insnHook and unmapHook hold the two hook callback shapes Engine
// supports, keyed by InsSyscall/InsCpuid for the former (only one
// hook per instruction ID, matching how internal/emulator uses it).
type insnHook func(*Engine)
type unmapHook func(eng *Engine, memType int, addr uint64, size int) bool

// Engine is one x86-64 CPU context: registers, memory, and the
// installed hooks. The zero value is not usable; use NewEngine.
type Engine struct {
	regs Registers
	mem  *Memory

	insnHooks map[int]insnHook
	unmapHook unmapHook

	stopRequested bool

	// curInstrEnd is the address just past the instruction currently
	// executing -- set by the fetch/decode/execute loop right before
	// running an instruction's semantics, and read by RIP-relative
	// memory operands (see operand.go's effAddr).
	curInstrEnd uint64
}

// NewEngine returns a fresh CPU context with no memory mapped and all
// registers zeroed.
func NewEngine() (*Engine, error) {
	return &Engine{
		mem:       newMemory(),
		insnHooks: make(map[int]insnHook),
	}, nil
}

// Close releases the engine. There is no host resource to free (no
// cgo handles, no C context) -- it exists purely for interface parity
// with uc.Engine.Close.
func (e *Engine) Close() error { return nil }

// -- memory -----------------------------------------------------------

func (e *Engine) MemMap(addr, size uint64, perms int) error {
	return e.mem.MemMap(addr, size, perms)
}

func (e *Engine) MemUnmap(addr, size uint64) error {
	return e.mem.MemUnmap(addr, size)
}

func (e *Engine) MemProtect(addr, size uint64, perms int) error {
	return e.mem.MemProtect(addr, size, perms)
}

// MemWrite writes data into guest memory, bypassing page protection
// bits -- this is the same "direct host access" semantics as
// uc_mem_write, used by callers like the syscall layer that need to
// write to guest memory the guest process itself may have mapped
// read-only.
func (e *Engine) MemWrite(addr uint64, data []byte) error {
	return e.mem.MemWrite(addr, data)
}

// MemRead reads size bytes of guest memory, bypassing page protection
// bits (see MemWrite).
func (e *Engine) MemRead(addr uint64, size int) ([]byte, error) {
	return e.mem.MemRead(addr, size)
}

// -- registers --------------------------------------------------------

func (e *Engine) RegRead(reg int) (uint64, error) {
	switch reg {
	case RegRIP:
		return e.regs.rip, nil
	case RegEFLAGS:
		return e.regs.rflags, nil
	case RegFSBASE:
		return e.regs.fsbase, nil
	case RegGSBASE:
		return e.regs.gsbase, nil
	case RegMXCSR:
		return uint64(e.regs.mxcsr), nil
	}
	if reg >= RegRAX && reg <= RegR15 {
		return e.regs.gpr[reg], nil
	}
	// XMM: return low 64 bits only (use RegReadXMM for the full 128).
	if reg >= RegXMM0 && reg <= RegXMM15 {
		lo, _ := e.regs.readXMM(reg - RegXMM0)
		return lo, nil
	}
	// YMM: return low 64 bits only (use RegReadYMM for the full 256).
	if reg >= RegYMM0 && reg <= RegYMM15 {
		lo, _ := e.regs.readXMM(reg - RegYMM0)
		return lo, nil
	}
	return 0, fmt.Errorf("cpu: RegRead: unknown register id %d", reg)
}

func (e *Engine) RegWrite(reg int, val uint64) error {
	switch reg {
	case RegRIP:
		e.regs.rip = val
		return nil
	case RegEFLAGS:
		e.regs.rflags = val
		return nil
	case RegFSBASE:
		e.regs.fsbase = val
		return nil
	case RegGSBASE:
		e.regs.gsbase = val
		return nil
	case RegMXCSR:
		e.regs.mxcsr = uint32(val)
		return nil
	}
	if reg >= RegRAX && reg <= RegR15 {
		e.regs.gpr[reg] = val
		return nil
	}
	return fmt.Errorf("cpu: RegWrite: unknown register id %d", reg)
}

// RegReadXMM returns the 128-bit contents of XMM[n] as a (lo, hi)
// uint64 pair (little-endian lane order: lo holds bytes 0-7, hi holds
// bytes 8-15).
func (e *Engine) RegReadXMM(n int) (lo, hi uint64, err error) {
	if n < 0 || n > 15 {
		return 0, 0, fmt.Errorf("cpu: RegReadXMM: index %d out of range", n)
	}
	l, h := e.regs.readXMM(n)
	return l, h, nil
}

// RegWriteXMM writes (lo, hi) into XMM[n], using SSE semantics (upper
// YMM bits are preserved).  To apply the VEX zero-upper rule, use
// RegWriteXMMVex instead.
func (e *Engine) RegWriteXMM(n int, lo, hi uint64) error {
	if n < 0 || n > 15 {
		return fmt.Errorf("cpu: RegWriteXMM: index %d out of range", n)
	}
	e.regs.writeXMM(n, lo, hi)
	return nil
}

// RegReadYMM returns all four 64-bit lanes of YMM[n]:
// lo0/lo1 are the low 128 bits (= XMM[n]), hi0/hi1 are the upper 128.
func (e *Engine) RegReadYMM(n int) (lo0, lo1, hi0, hi1 uint64, err error) {
	if n < 0 || n > 15 {
		return 0, 0, 0, 0, fmt.Errorf("cpu: RegReadYMM: index %d out of range", n)
	}
	a, b, c, d := e.regs.readYMM(n)
	return a, b, c, d, nil
}

// RegWriteYMM writes all four 64-bit lanes into YMM[n] (and
// consequently into the XMM[n] alias of its low half).
func (e *Engine) RegWriteYMM(n int, lo0, lo1, hi0, hi1 uint64) error {
	if n < 0 || n > 15 {
		return fmt.Errorf("cpu: RegWriteYMM: index %d out of range", n)
	}
	e.regs.writeYMM(n, lo0, lo1, hi0, hi1)
	return nil
}

// -- hooks --------------------------------------------------------------

// HookInsn registers cb to run whenever the given instruction ID
// (InsSyscall or InsCpuid) is decoded, in place of executing any
// built-in semantics for it (there are none -- SYSCALL and CPUID are
// meaningless without a hook, since this engine has no kernel or real
// CPUID data of its own).
//
// The RIP-advance behavior deliberately matches libunicorn's, which
// internal/emulator's hook callbacks already depend on:
//   - InsSyscall: after cb returns, RIP is auto-advanced past the
//     2-byte SYSCALL opcode, exactly as if the instruction fell
//     through normally. cb does not need to (and should not) touch
//     RIP itself.
//   - InsCpuid: RIP is left exactly where cb leaves it. cb is
//     responsible for advancing RIP past the 2-byte CPUID opcode
//     itself if it wants execution to continue past it.
func (e *Engine) HookInsn(insnID int, cb func(*Engine)) error {
	e.insnHooks[insnID] = cb
	return nil
}

// HookMemUnmapped registers cb to run when the guest accesses
// unmapped memory (or memory lacking the needed permission bit)
// during instruction fetch/decode/execute. Returning true tells the
// engine to retry the access once (the hook is expected to have
// mapped the needed memory itself, e.g. for a growable-stack style
// fault handler); false lets the fault propagate as an error from
// EmuStart, matching uc.Engine.HookMemUnmapped.
func (e *Engine) HookMemUnmapped(cb func(eng *Engine, memType int, addr uint64, size int) bool) error {
	e.unmapHook = cb
	return nil
}

// EmuStop halts emulation from within a hook callback. Mirrors
// uc.Engine.EmuStop.
func (e *Engine) EmuStop() error {
	e.stopRequested = true
	return nil
}

// EmuStart begins emulation at begin, running until an explicit
// EmuStop(), an unhandled fault, or (if until != 0) RIP reaching that
// address -- matching uc.Engine.EmuStart.
func (e *Engine) EmuStart(begin, until uint64) error {
	e.regs.rip = begin
	e.stopRequested = false
	for {
		if e.stopRequested {
			return nil
		}
		if until != 0 && e.regs.rip == until {
			return nil
		}

		pc := e.regs.rip
		d, err := e.decodeOne(pc)
		if err != nil {
			if !e.handleFault(err) {
				return err
			}
			continue // hook mapped the memory; retry the same instruction
		}
		e.curInstrEnd = pc + uint64(d.len)

		if d.insnID != noInsnHook {
			hook, ok := e.insnHooks[d.insnID]
			if !ok {
				return fmt.Errorf("cpu: %s at %#x with no hook installed", insnName(d.insnID), pc)
			}
			hook(e)
			if d.insnID == InsSyscall && !e.stopRequested {
				// Unicorn auto-advances RIP past SYSCALL once the
				// hook returns; CPUID's hook is responsible for
				// setting RIP itself (see HookInsn's doc comment).
				e.regs.rip = e.curInstrEnd
			}
			continue
		}

		branched, err := d.exec(e)
		if err != nil {
			if !e.handleFault(err) {
				return err
			}
			continue
		}
		if !branched {
			e.regs.rip = e.curInstrEnd
		}
	}
}

// handleFault dispatches an unmapped-memory error to the installed
// hook, if any, returning true if the hook says the access has been
// resolved and the faulting instruction should be retried.
func (e *Engine) handleFault(err error) bool {
	fe, ok := err.(*faultError)
	if !ok || e.unmapHook == nil {
		return false
	}
	return e.unmapHook(e, fe.MemType, fe.Addr, fe.Size)
}

func insnName(id int) string {
	switch id {
	case InsSyscall:
		return "syscall"
	case InsCpuid:
		return "cpuid"
	}
	return "instruction"
}
