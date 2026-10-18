package cpu

import "fmt"

type operandKind int

const (
	opndReg operandKind = iota
	opndMem
	opndImm
)

// segOverride marks that a memory operand carries a legacy FS/GS
// segment-override prefix, which real x86-64 (and this emulator) uses
// almost exclusively for thread-local storage access. It's a marker
// resolved lazily by effAddr, at execute time, rather than a base
// baked into addr at decode time -- deliberately mirroring how
// ripRelative/ripDisp already defer RIP-relative resolution below.
// That laziness isn't just tidiness: decoded instructions are cached
// by address (see Memory.decodeCache) and reused across every
// subsequent execution of that address, so any address arithmetic
// that depends on state which can change between executions -- like
// the FS/GS base, which a real program sets up via arch_prctl(2)
// during startup, generally *after* some of its own code (crt0/ifunc
// resolvers/etc.) has already run at least once -- must be resolved
// fresh on every call, or a cached instruction goes on using
// whatever base happened to be current the first time it ran,
// forever. (An earlier version of this emulator added the base
// directly to addr inside decode.go's applySeg, which was fine before
// decode caching existed but became a real correctness bug once
// caching was added: any FS/GS-relative access -- e.g. TLS variables,
// stack-protector canary checks, errno -- got permanently pinned to
// the wrong absolute address the moment its instruction was decoded
// before the "real" base was established, silently corrupting
// whatever unrelated memory now lived at the stale address instead.)
type segOverride int

const (
	segOverrideNone segOverride = iota
	segOverrideFS
	segOverrideGS
)

// operand is a resolved instruction operand. For opndMem, there are
// three mutually exclusive ways the final address is computed --
// checked in this order by effAddr:
//
//  1. ripRelative: e.curInstrEnd + ripDisp (RIP-relative addressing;
//     curInstrEnd isn't known until the whole instruction, including
//     any trailing immediate, has finished decoding -- see decode.go).
//  2. memBaseIndex: sums the CURRENT contents of memBaseReg (if
//     haveBase) and memIndexReg*memScale (if haveIndex) with memDisp.
//     This is the general ModRM+SIB form (see decodeModRM) and is
//     deliberately symbolic rather than a precomputed number: base/
//     index are register *indices*, resolved fresh each time effAddr
//     runs, not values baked in at decode time.
//  3. Otherwise: addr is used directly, already fully resolved.
//
// Why (2) matters as much as (1): decoded instructions are cached by
// address (see Memory.decodeCache) and reused across every subsequent
// execution of that address. Almost every memory operand in real code
// is register-relative -- array/loop indexing, stack locals, struct
// fields -- so if decodeModRM baked in whatever the base/index
// registers happened to hold the first time an instruction was
// decoded (which is what an earlier version of this file did, being
// a computed uint64 stored straight into addr), every cached reuse of
// that instruction would keep reading/writing the *same* frozen
// address forever regardless of how the registers actually changed
// on each pass through a loop -- e.g. a "scan array for a NULL
// terminator" loop incrementing an index register would spin forever,
// since the load that's supposed to see the new index keeps loading
// from wherever the first iteration pointed. seg (see segOverride)
// already had the same lazy-resolution treatment for exactly this
// reason.
type operand struct {
	kind operandKind
	reg  int // opndReg: register index 0-15
	rex  bool

	addr        uint64
	ripRelative bool
	ripDisp     int64

	memBaseIndex bool // if set, addr above is ignored; use the fields below instead
	memBaseReg   int
	haveBase     bool
	memIndexReg  int
	haveIndex    bool
	memScale     uint64
	memDisp      int64

	seg segOverride

	imm uint64 // opndImm: value, already sign/zero-extended into 64 bits as appropriate
}

func regOperand(reg int, rex bool) operand { return operand{kind: opndReg, reg: reg, rex: rex} }
func immOperand(v uint64) operand          { return operand{kind: opndImm, imm: v} }
func memOperand(addr uint64) operand       { return operand{kind: opndMem, addr: addr} }
func memOperandRIP(disp int64) operand {
	return operand{kind: opndMem, ripRelative: true, ripDisp: disp}
}

// memOperandBaseIndex builds a ModRM/SIB-style memory operand whose
// address is computed fresh from current register contents every
// time effAddr resolves it -- see operand's doc comment above.
func memOperandBaseIndex(baseReg int, haveBase bool, indexReg int, haveIndex bool, scale uint64, disp int64) operand {
	return operand{
		kind: opndMem, memBaseIndex: true,
		memBaseReg: baseReg, haveBase: haveBase,
		memIndexReg: indexReg, haveIndex: haveIndex,
		memScale: scale, memDisp: disp,
	}
}

// effAddr resolves a memory operand's final address, applying its
// FS/GS segment override (if any) against the *current* base -- see
// segOverride's and operand's doc comments for why this, and the
// base/index register reads below, must happen here at access time
// rather than having been folded into addr back when the operand was
// decoded.
func (e *Engine) effAddr(o operand) uint64 {
	var addr uint64
	switch {
	case o.ripRelative:
		addr = e.curInstrEnd + uint64(o.ripDisp)
	case o.memBaseIndex:
		if o.haveBase {
			addr += e.regs.read64(o.memBaseReg)
		}
		if o.haveIndex {
			addr += e.regs.read64(o.memIndexReg) * o.memScale
		}
		if o.memDisp < 0 {
			addr -= uint64(-o.memDisp)
		} else {
			addr += uint64(o.memDisp)
		}
	default:
		addr = o.addr
	}
	switch o.seg {
	case segOverrideFS:
		addr += e.regs.fsbase
	case segOverrideGS:
		addr += e.regs.gsbase
	}
	return addr
}

func leToU64(b []byte) uint64 {
	var v uint64
	for i, x := range b {
		v |= uint64(x) << uint(8*i)
	}
	return v
}

func u64ToLE(v uint64, width int) []byte {
	b := make([]byte, width)
	for i := 0; i < width; i++ {
		b[i] = byte(v >> uint(8*i))
	}
	return b
}

// readOperand reads width bytes from o (a register, memory location,
// or immediate).
func (e *Engine) readOperand(o operand, width int) (uint64, error) {
	switch o.kind {
	case opndReg:
		return e.regs.readWidth(o.reg, width, o.rex), nil
	case opndImm:
		return o.imm, nil
	case opndMem:
		buf, err := e.mem.readChecked(e.effAddr(o), width, ProtRead)
		if err != nil {
			return 0, err
		}
		return leToU64(buf), nil
	}
	return 0, fmt.Errorf("cpu: readOperand: bad operand kind %d", o.kind)
}

// writeOperand writes val (truncated to width bytes) into o, which
// must be a register or memory operand.
func (e *Engine) writeOperand(o operand, width int, val uint64) error {
	switch o.kind {
	case opndReg:
		e.regs.writeWidth(o.reg, width, o.rex, val)
		return nil
	case opndMem:
		return e.mem.writeChecked(e.effAddr(o), u64ToLE(val, width), ProtWrite)
	}
	return fmt.Errorf("cpu: writeOperand: cannot write to operand kind %d", o.kind)
}

// leaAddr returns the address a memory operand refers to without
// dereferencing it -- what LEA needs.
func (e *Engine) leaAddr(o operand) (uint64, error) {
	if o.kind != opndMem {
		return 0, fmt.Errorf("cpu: LEA: operand is not memory")
	}
	return e.effAddr(o), nil
}

func signExtend(v uint64, fromBits int) uint64 {
	shift := 64 - fromBits
	return uint64(int64(v<<uint(shift)) >> uint(shift))
}
