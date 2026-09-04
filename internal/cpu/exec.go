package cpu

import (
	"fmt"
	"math/bits"
)

func (e *Engine) push64(v uint64) error {
	sp := e.regs.gpr[RegRSP] - 8
	if err := e.mem.writeChecked(sp, u64ToLE(v, 8), ProtWrite); err != nil {
		return err
	}
	e.regs.gpr[RegRSP] = sp
	return nil
}

func (e *Engine) pop64() (uint64, error) {
	sp := e.regs.gpr[RegRSP]
	buf, err := e.mem.readChecked(sp, 8, ProtRead)
	if err != nil {
		return 0, err
	}
	e.regs.gpr[RegRSP] = sp + 8
	return leToU64(buf), nil
}

// grp3Op implements the 0xF6/0xF7 opcode group's /2-/7 operations
// (NOT, NEG, MUL, IMUL, DIV, IDIV -- /0 and /1, TEST, are handled by
// the caller since they need an immediate instead of just rm).
func (e *Engine) grp3Op(idx int, rm operand, w int) error {
	switch idx {
	case 2: // NOT
		a, err := e.readOperand(rm, w)
		if err != nil {
			return err
		}
		return e.writeOperand(rm, w, ^a&maskWidth(w))
	case 3: // NEG
		a, err := e.readOperand(rm, w)
		if err != nil {
			return err
		}
		result := e.subWithFlags(0, a, w)
		e.setFlag(flagCF, a != 0)
		return e.writeOperand(rm, w, result)
	case 4: // MUL r/m: unsigned rAX * rm -> rDX:rAX
		a, err := e.readOperand(rm, w)
		if err != nil {
			return err
		}
		ax, _ := e.readOperand(regOperand(0, true), w)
		hi, lo := mulUnsigned(ax, a, w)
		e.writeOperand(regOperand(0, true), w, lo)
		e.writeOperand(regOperand(2, true), w, hi)
		overflow := hi != 0
		e.setFlag(flagCF, overflow)
		e.setFlag(flagOF, overflow)
		return nil
	case 5: // IMUL r/m: signed rAX * rm -> rDX:rAX
		a, err := e.readOperand(rm, w)
		if err != nil {
			return err
		}
		ax, _ := e.readOperand(regOperand(0, true), w)
		hi, lo := mulSigned(ax, a, w)
		e.writeOperand(regOperand(0, true), w, lo)
		e.writeOperand(regOperand(2, true), w, hi)
		overflow := hi != extendSignHi(lo, w)
		e.setFlag(flagCF, overflow)
		e.setFlag(flagOF, overflow)
		return nil
	case 6: // DIV r/m: unsigned rDX:rAX / rm -> quotient rAX, remainder rDX
		divisor, err := e.readOperand(rm, w)
		if err != nil {
			return err
		}
		if divisor == 0 {
			return fmt.Errorf("cpu: division by zero")
		}
		ax, _ := e.readOperand(regOperand(0, true), w)
		dx, _ := e.readOperand(regOperand(2, true), w)
		q, r, err := divUnsigned(dx, ax, divisor, w)
		if err != nil {
			return err
		}
		e.writeOperand(regOperand(0, true), w, q)
		e.writeOperand(regOperand(2, true), w, r)
		return nil
	case 7: // IDIV r/m: signed rDX:rAX / rm -> quotient rAX, remainder rDX
		divisor, err := e.readOperand(rm, w)
		if err != nil {
			return err
		}
		if divisor == 0 {
			return fmt.Errorf("cpu: division by zero")
		}
		ax, _ := e.readOperand(regOperand(0, true), w)
		dx, _ := e.readOperand(regOperand(2, true), w)
		q, r, err := divSigned(dx, ax, divisor, w)
		if err != nil {
			return err
		}
		e.writeOperand(regOperand(0, true), w, q)
		e.writeOperand(regOperand(2, true), w, r)
		return nil
	}
	return fmt.Errorf("cpu: unsupported grp3 /%d", idx)
}

// imul2 implements the two/three-operand IMUL forms (0x0F 0xAF, and
// 0x69/0x6B via the decode.go caller): dst = dst_or_rm * src, signed,
// truncated to width, with CF/OF set iff the full-width product
// didn't fit in the truncated result.
func (e *Engine) imul2(dst operand, a, b uint64, w int) error {
	hi, lo := mulSigned(a, b, w)
	overflow := hi != extendSignHi(lo, w)
	e.setFlag(flagCF, overflow)
	e.setFlag(flagOF, overflow)
	return e.writeOperand(dst, w, lo)
}

// extendSignHi returns what the "high half" of a width-wide value
// would be if lo were sign-extended to double width -- used to detect
// IMUL truncation overflow generically across widths.
func extendSignHi(lo uint64, w int) uint64 {
	if int64(signExtend(lo, w*8)) < 0 {
		return maskWidth(w)
	}
	return 0
}

func mulUnsigned(a, b uint64, w int) (hi, lo uint64) {
	mask := maskWidth(w)
	a &= mask
	b &= mask
	if w == 8 {
		h, l := bits.Mul64(a, b)
		return h, l
	}
	full := a * b
	return (full >> uint(w*8)) & mask, full & mask
}

func mulSigned(a, b uint64, w int) (hi, lo uint64) {
	sa := int64(signExtend(a, w*8))
	sb := int64(signExtend(b, w*8))
	if w == 8 {
		h, l := bits.Mul64(uint64(sa), uint64(sb))
		// bits.Mul64 is unsigned; correct for signed operands by
		// subtracting b if a<0 and a if b<0 (standard correction).
		if sa < 0 {
			h -= uint64(sb)
		}
		if sb < 0 {
			h -= uint64(sa)
		}
		return h, l
	}
	full := sa * sb
	mask := maskWidth(w)
	return uint64(full>>uint(w*8)) & mask, uint64(full) & mask
}

func divUnsigned(dxHi, axLo, divisor uint64, w int) (q, r uint64, err error) {
	mask := maskWidth(w)
	dxHi &= mask
	axLo &= mask
	divisor &= mask
	if w == 8 {
		if dxHi >= divisor {
			return 0, 0, fmt.Errorf("cpu: DIV overflow")
		}
		q, r = bits.Div64(dxHi, axLo, divisor)
		return q, r, nil
	}
	full := (dxHi << uint(w*8)) | axLo
	qq := full / divisor
	if qq > mask {
		return 0, 0, fmt.Errorf("cpu: DIV overflow")
	}
	return qq, full % divisor, nil
}

// divSigned computes the IDIV rDX:rAX / divisor -> (quotient, remainder)
// for 8/16/32-bit widths exactly. For 64-bit it needs a 128-bit signed
// dividend, which Go's math/bits has no signed divide helper for; it
// special-cases the case every compiler actually generates (CQO
// immediately before IDIV, so dxHi is exactly the sign-extension of
// axLo and the true dividend fits in 64 bits) and errors on anything
// else rather than silently computing a wrong answer.
func divSigned(dxHi, axLo, divisor uint64, w int) (q, r uint64, err error) {
	if divisor == 0 {
		return 0, 0, fmt.Errorf("cpu: division by zero")
	}
	if w == 8 {
		if dxHi != 0 && dxHi != ^uint64(0) {
			return 0, 0, fmt.Errorf("cpu: 64-bit IDIV with a dividend >64 significant bits is not supported")
		}
		dividend := int64(axLo)
		sdiv := int64(divisor)
		return uint64(dividend / sdiv), uint64(dividend % sdiv), nil
	}
	mask := maskWidth(w)
	raw := (dxHi&mask)<<uint(w*8) | (axLo & mask)
	dividend := int64(signExtend(raw, w*16))
	sdiv := int64(signExtend(divisor, w*8))
	qq := dividend / sdiv
	rr := dividend % sdiv
	return uint64(qq) & mask, uint64(rr) & mask, nil
}

// -- string instructions ----------------------------------------------
//
// Each str* method runs the whole REP loop (if any) in one Go loop
// rather than being interruptible mid-count the way real hardware
// microcode is -- see the package doc comment for why that's fine
// here. repCount reports how many iterations to run and whether this
// is a bounded-by-ZF compare loop (CMPS/SCAS under REPE/REPNE);
// strIndexDelta gives the per-iteration +/-width step for DF.

func (e *Engine) strIndexDelta(w int) uint64 {
	if e.flag(flagDF) {
		return ^uint64(w) + 1 // -w, two's complement
	}
	return uint64(w)
}

// repIterations returns the number of times to run the loop body:
// 1 for no REP prefix (the instruction still executes exactly once),
// or the initial RCX for REP/REPE/REPNE (which is 0 iterations if
// RCX started at 0 -- REP never runs the body "at least once").
func (e *Engine) repIterations(rep repKind) uint64 {
	if rep == repNone {
		return 1
	}
	return e.regs.gpr[RegRCX]
}

func (e *Engine) strMovs(w int, rep repKind) error {
	delta := e.strIndexDelta(w)
	n := e.repIterations(rep)
	for i := uint64(0); i < n; i++ {
		buf, err := e.mem.readChecked(e.regs.gpr[RegRSI], w, ProtRead)
		if err != nil {
			return err
		}
		if err := e.mem.writeChecked(e.regs.gpr[RegRDI], buf, ProtWrite); err != nil {
			return err
		}
		e.regs.gpr[RegRSI] += delta
		e.regs.gpr[RegRDI] += delta
		if rep != repNone {
			e.regs.gpr[RegRCX]--
		}
	}
	return nil
}

func (e *Engine) strStos(w int, rep repKind, rex bool) error {
	delta := e.strIndexDelta(w)
	val := e.regs.readWidth(RegRAX, w, rex)
	n := e.repIterations(rep)
	buf := u64ToLE(val, w)
	for i := uint64(0); i < n; i++ {
		if err := e.mem.writeChecked(e.regs.gpr[RegRDI], buf, ProtWrite); err != nil {
			return err
		}
		e.regs.gpr[RegRDI] += delta
		if rep != repNone {
			e.regs.gpr[RegRCX]--
		}
	}
	return nil
}

func (e *Engine) strLods(w int, rep repKind, rex bool) error {
	delta := e.strIndexDelta(w)
	n := e.repIterations(rep)
	for i := uint64(0); i < n; i++ {
		buf, err := e.mem.readChecked(e.regs.gpr[RegRSI], w, ProtRead)
		if err != nil {
			return err
		}
		e.regs.writeWidth(RegRAX, w, rex, leToU64(buf))
		e.regs.gpr[RegRSI] += delta
		if rep != repNone {
			e.regs.gpr[RegRCX]--
		}
	}
	return nil
}

func (e *Engine) strCmps(w int, rep repKind) error {
	delta := e.strIndexDelta(w)
	n := e.repIterations(rep)
	for i := uint64(0); i < n; i++ {
		a, err := e.mem.readChecked(e.regs.gpr[RegRSI], w, ProtRead)
		if err != nil {
			return err
		}
		b, err := e.mem.readChecked(e.regs.gpr[RegRDI], w, ProtRead)
		if err != nil {
			return err
		}
		e.subWithFlags(leToU64(a), leToU64(b), w)
		e.regs.gpr[RegRSI] += delta
		e.regs.gpr[RegRDI] += delta
		if rep != repNone {
			e.regs.gpr[RegRCX]--
			if rep == repZ && !e.flag(flagZF) {
				break
			}
			if rep == repNZ && e.flag(flagZF) {
				break
			}
		}
	}
	return nil
}

func (e *Engine) strScas(w int, rep repKind, rex bool) error {
	delta := e.strIndexDelta(w)
	n := e.repIterations(rep)
	for i := uint64(0); i < n; i++ {
		a := e.regs.readWidth(RegRAX, w, rex)
		b, err := e.mem.readChecked(e.regs.gpr[RegRDI], w, ProtRead)
		if err != nil {
			return err
		}
		e.subWithFlags(a, leToU64(b), w)
		e.regs.gpr[RegRDI] += delta
		if rep != repNone {
			e.regs.gpr[RegRCX]--
			if rep == repZ && !e.flag(flagZF) {
				break
			}
			if rep == repNZ && e.flag(flagZF) {
				break
			}
		}
	}
	return nil
}

// shiftGrp2 implements SHL/SHR/SAR/ROL/ROR (the 0xC0/0xC1/0xD0-0xD3
// opcode group). count has already been masked by the caller-visible
// modulo (x86 masks the effective shift count by 0x1F for 16/32-bit
// operands and 0x3F for 64-bit ones, applied here).
func (e *Engine) shiftGrp2(idx int, rm operand, w, rawCount int) error {
	countMask := 0x1F
	if w == 8 {
		countMask = 0x3F
	}
	count := rawCount & countMask
	a, err := e.readOperand(rm, w)
	if err != nil {
		return err
	}
	if count == 0 {
		return nil // flags untouched per x86 semantics
	}
	mask := maskWidth(w)
	a &= mask
	var result uint64
	var cf bool
	switch idx {
	case 4, 6: // SHL/SAL
		if count <= w*8 {
			result = (a << uint(count)) & mask
			cf = count <= w*8 && (a>>uint(w*8-count))&1 != 0
		}
		e.shiftFlags("shl", a, result, w, count, cf)
	case 5: // SHR
		result = a >> uint(count)
		cf = (a>>uint(count-1))&1 != 0
		e.shiftFlags("shr", a, result, w, count, cf)
	case 7: // SAR
		sv := int64(signExtend(a, w*8))
		result = uint64(sv>>uint(count)) & mask
		cf = (a>>uint(count-1))&1 != 0
		e.shiftFlags("sar", a, result, w, count, cf)
	case 0: // ROL
		n := uint(w * 8)
		c := uint(count) % n
		result = ((a << c) | (a >> (n - c))) & mask
		cf = result&1 != 0
		e.shiftFlags("rol", a, result, w, count, cf)
	case 1: // ROR
		n := uint(w * 8)
		c := uint(count) % n
		result = ((a >> c) | (a << (n - c))) & mask
		cf = result&signBit(w) != 0
		e.shiftFlags("ror", a, result, w, count, cf)
	default:
		return fmt.Errorf("cpu: unsupported shift group /%d", idx)
	}
	return e.writeOperand(rm, w, result)
}
