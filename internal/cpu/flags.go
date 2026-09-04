package cpu

import "math/bits"

// maskWidth returns a mask selecting the low width*8 bits.
func maskWidth(width int) uint64 {
	if width >= 8 {
		return ^uint64(0)
	}
	return (uint64(1) << uint(width*8)) - 1
}

// signBit returns the sign-bit mask for the given operand width.
func signBit(width int) uint64 {
	return uint64(1) << uint(width*8-1)
}

func parity8(b uint8) bool {
	return bits.OnesCount8(b)%2 == 0
}

// setFlag sets or clears a single EFLAGS bit.
func (e *Engine) setFlag(mask uint64, on bool) {
	if on {
		e.regs.rflags |= mask
	} else {
		e.regs.rflags &^= mask
	}
}

func (e *Engine) flag(mask uint64) bool { return e.regs.rflags&mask != 0 }

// setResultFlags sets SF/ZF/PF from a result value (used by every
// instruction that produces a result -- logic ops, shifts, INC/DEC,
// arithmetic).
func (e *Engine) setResultFlags(result uint64, width int) {
	r := result & maskWidth(width)
	e.setFlag(flagZF, r == 0)
	e.setFlag(flagSF, r&signBit(width) != 0)
	e.setFlag(flagPF, parity8(uint8(r)))
}

// addWithFlags computes a+b at the given width, sets CF/PF/AF/ZF/SF/OF
// to match real hardware, and returns the (width-masked) result.
func (e *Engine) addWithFlags(a, b uint64, width int) uint64 {
	return e.addWithFlagsCarry(a, b, width, 0)
}

// addWithFlagsCarry computes a+b+cin (cin is 0 or 1) at the given
// width -- ADD uses cin=0, ADC uses the incoming CF. AF/OF are
// computed from a, b, and the final result; this is the standard
// simplification used by real hardware and every emulator that isn't
// modeling decimal-adjust corner cases bit-for-bit, which nothing in
// a normal compiled program depends on (see the package doc comment).
func (e *Engine) addWithFlagsCarry(a, b uint64, width int, cin uint64) uint64 {
	mask := maskWidth(width)
	a &= mask
	b &= mask

	var result uint64
	var cf bool
	if width >= 8 {
		sum1, c1 := bits.Add64(a, b, 0)
		sum2, c2 := bits.Add64(sum1, cin, 0)
		result = sum2
		cf = (c1 | c2) != 0
	} else {
		sum := a + b + cin
		result = sum & mask
		cf = sum > mask
	}

	sa, sb, sr := a&signBit(width) != 0, b&signBit(width) != 0, result&signBit(width) != 0
	of := sa == sb && sr != sa
	af := (a^b^result)&0x10 != 0

	e.setFlag(flagCF, cf)
	e.setFlag(flagOF, of)
	e.setFlag(flagAF, af)
	e.setResultFlags(result, width)
	return result
}

// subWithFlags computes a-b at the given width (used by SUB and CMP)
// and sets flags to match real hardware.
func (e *Engine) subWithFlags(a, b uint64, width int) uint64 {
	return e.subWithFlagsBorrow(a, b, width, 0)
}

// subWithFlagsBorrow computes a-b-bin (bin is 0 or 1) -- SUB/CMP use
// bin=0, SBB uses the incoming CF.
func (e *Engine) subWithFlagsBorrow(a, b uint64, width int, bin uint64) uint64 {
	mask := maskWidth(width)
	a &= mask
	b &= mask

	var result uint64
	var cf bool
	if width >= 8 {
		diff1, b1 := bits.Sub64(a, b, 0)
		diff2, b2 := bits.Sub64(diff1, bin, 0)
		result = diff2
		cf = (b1 | b2) != 0
	} else {
		d := a - b - bin
		result = d & mask
		cf = a < b+bin
	}

	sa, sb, sr := a&signBit(width) != 0, b&signBit(width) != 0, result&signBit(width) != 0
	of := sa != sb && sr != sa
	af := (a^b^result)&0x10 != 0

	e.setFlag(flagCF, cf)
	e.setFlag(flagOF, of)
	e.setFlag(flagAF, af)
	e.setResultFlags(result, width)
	return result
}

// logicFlags sets the flags for AND/OR/XOR/TEST: CF and OF are always
// cleared, AF is undefined on real hardware (cleared here), and
// SF/ZF/PF come from the result.
func (e *Engine) logicFlags(result uint64, width int) {
	e.setFlag(flagCF, false)
	e.setFlag(flagOF, false)
	e.setFlag(flagAF, false)
	e.setResultFlags(result, width)
}

// incFlags/decFlags set OF/AF/SF/ZF/PF for INC/DEC, which -- unlike
// ADD/SUB -- must leave CF exactly as it was.
func (e *Engine) incFlags(a uint64, width int) uint64 {
	savedCF := e.flag(flagCF)
	result := e.addWithFlags(a, 1, width)
	e.setFlag(flagCF, savedCF)
	return result
}

func (e *Engine) decFlags(a uint64, width int) uint64 {
	savedCF := e.flag(flagCF)
	result := e.subWithFlags(a, 1, width)
	e.setFlag(flagCF, savedCF)
	return result
}

// shiftFlags applies the (count-dependent) flag rules for SHL/SHR/
// SAR/ROL/ROR given the pre-shift operand, the post-shift result, the
// masked shift count actually applied, and which bit was last shifted
// out (for CF). count==0 must be handled by the caller: no flags at
// all are touched in that case.
func (e *Engine) shiftFlags(op string, before, result uint64, width, count int, cf bool) {
	e.setFlag(flagCF, cf)
	switch op {
	case "shl", "sal":
		if count == 1 {
			of := (result&signBit(width) != 0) != cf
			e.setFlag(flagOF, of)
		}
		e.setResultFlags(result, width)
	case "shr":
		if count == 1 {
			e.setFlag(flagOF, before&signBit(width) != 0)
		}
		e.setResultFlags(result, width)
	case "sar":
		if count == 1 {
			e.setFlag(flagOF, false)
		}
		e.setResultFlags(result, width)
	case "rol", "ror":
		if count == 1 {
			msb := result&signBit(width) != 0
			e.setFlag(flagOF, msb != cf)
		}
		// ROL/ROR do not touch SF/ZF/AF/PF.
	}
}
