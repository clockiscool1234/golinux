package cpu

import "fmt"

// decodeTwoByte decodes everything after a 0x0F escape byte.  The
// legacy/REX prefix state and helper closures are threaded through from
// decodeOne since 0F-prefixed instructions share the same operand-size
// and segment-override rules as one-byte ones.
//
// SSE/AVX prefix context is conveyed by the opSize16 and rep parameters:
//
//	opSize16 true  → 66 0F (packed-double / SSE2-integer)
//	rep == repZ    → F3 0F (scalar-single)
//	rep == repNZ   → F2 0F (scalar-double)
//	otherwise      → NP   (packed-single)
func (e *Engine) decodeTwoByte(
	c *cursor,
	rexPresent, rexW, rexR, rexX, rexB, opSize16 bool,
	rep repKind,
	applySeg func(operand) operand,
	width func(byteOp bool) int,
	finish func(func(*Engine) (bool, error)) (*decoded, error),
) (*decoded, error) {
	op2, err := c.u8()
	if err != nil {
		return nil, err
	}

	// ── Existing general-purpose 0F opcodes ──────────────────────────────
	switch {
	case op2 == 0x05: // SYSCALL
		return &decoded{len: c.pos, insnID: InsSyscall}, nil
	case op2 == 0xA2: // CPUID
		return &decoded{len: c.pos, insnID: InsCpuid}, nil

	case op2 >= 0x80 && op2 <= 0x8F: // Jcc rel32
		cc := int(op2 - 0x80)
		rel, err := c.i32()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			if e.evalCC(cc) {
				e.regs.rip = e.curInstrEnd + uint64(int64(rel))
				return true, nil
			}
			return false, nil
		})

	case op2 >= 0x90 && op2 <= 0x9F: // SETcc r/m8
		cc := int(op2 - 0x90)
		mr, err := decodeModRM(e, c, rexR, rexX, rexB)
		if err != nil {
			return nil, err
		}
		rm := applySeg(mr.rm)
		return finish(func(e *Engine) (bool, error) {
			v := uint64(0)
			if e.evalCC(cc) {
				v = 1
			}
			return false, e.writeOperand(rm, 1, v)
		})

	case op2 >= 0x40 && op2 <= 0x4F: // CMOVcc
		cc := int(op2 - 0x40)
		w := width(false)
		mr, err := decodeModRM(e, c, rexR, rexX, rexB)
		if err != nil {
			return nil, err
		}
		rm := applySeg(mr.rm)
		reg := regOperand(mr.regField, rexPresent)
		return finish(func(e *Engine) (bool, error) {
			if !e.evalCC(cc) {
				return false, nil
			}
			v, err := e.readOperand(rm, w)
			if err != nil {
				return false, err
			}
			return false, e.writeOperand(reg, w, v)
		})

	case op2 == 0xB6, op2 == 0xB7: // MOVZX
		srcW := 1
		if op2 == 0xB7 {
			srcW = 2
		}
		dstW := width(false)
		mr, err := decodeModRM(e, c, rexR, rexX, rexB)
		if err != nil {
			return nil, err
		}
		rm := applySeg(mr.rm)
		reg := regOperand(mr.regField, rexPresent)
		return finish(func(e *Engine) (bool, error) {
			v, err := e.readOperand(rm, srcW)
			if err != nil {
				return false, err
			}
			return false, e.writeOperand(reg, dstW, v)
		})

	case op2 == 0xBE, op2 == 0xBF: // MOVSX
		srcW := 1
		if op2 == 0xBF {
			srcW = 2
		}
		dstW := width(false)
		mr, err := decodeModRM(e, c, rexR, rexX, rexB)
		if err != nil {
			return nil, err
		}
		rm := applySeg(mr.rm)
		reg := regOperand(mr.regField, rexPresent)
		return finish(func(e *Engine) (bool, error) {
			v, err := e.readOperand(rm, srcW)
			if err != nil {
				return false, err
			}
			return false, e.writeOperand(reg, dstW, signExtend(v, srcW*8))
		})

	case op2 == 0xAF: // IMUL r, r/m
		w := width(false)
		mr, err := decodeModRM(e, c, rexR, rexX, rexB)
		if err != nil {
			return nil, err
		}
		rm := applySeg(mr.rm)
		reg := regOperand(mr.regField, rexPresent)
		return finish(func(e *Engine) (bool, error) {
			a, err := e.readOperand(reg, w)
			if err != nil {
				return false, err
			}
			b, err := e.readOperand(rm, w)
			if err != nil {
				return false, err
			}
			return false, e.imul2(reg, a, b, w)
		})

	case op2 == 0x1F: // multi-byte NOP
		if _, err := decodeModRM(e, c, rexR, rexX, rexB); err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) { return false, nil })

	case op2 == 0x1E: // ENDBR64/ENDBR32 or reserved NOP
		if b, err := c.peekByte(); err == nil && (b == 0xFA || b == 0xFB) {
			c.pos++
			return finish(func(e *Engine) (bool, error) { return false, nil })
		}
		if _, err := decodeModRM(e, c, rexR, rexX, rexB); err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) { return false, nil })

	// ── SHLD / SHRD ───────────────────────────────────────────────────
	case op2 == 0xA4, op2 == 0xA5: // SHLD r/m, r, imm8 / SHLD r/m, r, CL
		w := width(false)
		mr, err := decodeModRM(e, c, rexR, rexX, rexB)
		if err != nil {
			return nil, err
		}
		rm := applySeg(mr.rm)
		reg := regOperand(mr.regField, rexPresent)
		var immByte *uint8
		if op2 == 0xA4 {
			v, err := c.u8()
			if err != nil {
				return nil, err
			}
			immByte = &v
		}
		return finish(func(e *Engine) (bool, error) {
			dst, err := e.readOperand(rm, w)
			if err != nil {
				return false, err
			}
			src, err := e.readOperand(reg, w)
			if err != nil {
				return false, err
			}
			var cnt int
			if immByte != nil {
				cnt = int(*immByte)
			} else {
				cnt = int(e.regs.gpr[RegRCX] & 0xFF)
			}
			bits := w * 8
			cnt &= bits - 1
			if cnt == 0 {
				return false, nil
			}
			mask := maskWidth(w)
			result := ((dst << uint(cnt)) | (src >> uint(bits-cnt))) & mask
			e.setFlag(flagCF, (dst>>uint(bits-cnt))&1 != 0)
			e.setFlag(flagZF, result == 0)
			e.setFlag(flagSF, result>>uint(bits-1) != 0)
			e.setFlag(flagOF, cnt == 1 && (result>>uint(bits-1)) != (dst>>uint(bits-1)))
			return false, e.writeOperand(rm, w, result)
		})

	case op2 == 0xAC, op2 == 0xAD: // SHRD r/m, r, imm8 / SHRD r/m, r, CL
		w := width(false)
		mr, err := decodeModRM(e, c, rexR, rexX, rexB)
		if err != nil {
			return nil, err
		}
		rm := applySeg(mr.rm)
		reg := regOperand(mr.regField, rexPresent)
		var immByte *uint8
		if op2 == 0xAC {
			v, err := c.u8()
			if err != nil {
				return nil, err
			}
			immByte = &v
		}
		return finish(func(e *Engine) (bool, error) {
			dst, err := e.readOperand(rm, w)
			if err != nil {
				return false, err
			}
			src, err := e.readOperand(reg, w)
			if err != nil {
				return false, err
			}
			var cnt int
			if immByte != nil {
				cnt = int(*immByte)
			} else {
				cnt = int(e.regs.gpr[RegRCX] & 0xFF)
			}
			bits := w * 8
			cnt &= bits - 1
			if cnt == 0 {
				return false, nil
			}
			mask := maskWidth(w)
			result := ((dst >> uint(cnt)) | (src << uint(bits-cnt))) & mask
			e.setFlag(flagCF, (dst>>uint(cnt-1))&1 != 0)
			e.setFlag(flagZF, result == 0)
			e.setFlag(flagSF, result>>uint(bits-1) != 0)
			e.setFlag(flagOF, cnt == 1 && (result>>uint(bits-1)) != (dst>>uint(bits-1)))
			return false, e.writeOperand(rm, w, result)
		})

	// ── BT / BSF / BSR / POPCNT / LZCNT ─────────────────────────────────
	case op2 == 0xA3, op2 == 0xAB, op2 == 0xB3, op2 == 0xBB: // BT/BTS/BTR/BTC r/m, r
		mr, err := decodeModRM(e, c, rexR, rexX, rexB)
		if err != nil {
			return nil, err
		}
		rm := applySeg(mr.rm)
		reg := regOperand(mr.regField, rexPresent)
		w := width(false)
		op := op2
		return finish(func(e *Engine) (bool, error) {
			bit, err := e.readOperand(reg, w)
			if err != nil {
				return false, err
			}
			if rm.kind == opndReg {
				bit &= uint64(w)*8 - 1
			} else {
				// Memory bit-string semantics: bit is a signed offset
				// from the base address, and we read exactly 1 byte.
				bitOff := int64(bit)
				byteOff := bitOff / 8
				if bitOff < 0 && bitOff%8 != 0 {
					byteOff--
				}
				bit &= 7
				rm.addr = uint64(int64(e.effAddr(rm)) + byteOff)
				rm.ripRelative = false
				w = 1 // Read/write only the targeted byte
			}
			base, err := e.readOperand(rm, w)
			if err != nil {
				return false, err
			}
			e.setFlag(flagCF, (base>>bit)&1 != 0)
			switch op {
			case 0xAB: // BTS
				return false, e.writeOperand(rm, w, base|(1<<bit))
			case 0xB3: // BTR
				return false, e.writeOperand(rm, w, base&^(1<<bit))
			case 0xBB: // BTC
				return false, e.writeOperand(rm, w, base^(1<<bit))
			}
			return false, nil // BT: no write
		})
	case op2 == 0xBA: // BT/BTS/BTR/BTC r/m, imm8
		mr, err := decodeModRM(e, c, rexR, rexX, rexB)
		if err != nil {
			return nil, err
		}
		rm := applySeg(mr.rm)
		w := width(false)
		imm, err := c.u8()
		if err != nil {
			return nil, err
		}
		idx := mr.regField & 7
		return finish(func(e *Engine) (bool, error) {
			base, err := e.readOperand(rm, w)
			if err != nil {
				return false, err
			}
			bit := uint64(imm) & (uint64(w)*8 - 1)
			e.setFlag(flagCF, (base>>bit)&1 != 0)
			switch idx {
			case 5: // BTS
				return false, e.writeOperand(rm, w, base|(1<<bit))
			case 6: // BTR
				return false, e.writeOperand(rm, w, base&^(1<<bit))
			case 7: // BTC
				return false, e.writeOperand(rm, w, base^(1<<bit))
			}
			return false, nil
		})
	case op2 == 0xB0, op2 == 0xB1: // CMPXCHG r/m, r
		byteOp := op2 == 0xB0
		w := width(byteOp)
		mr, err := decodeModRM(e, c, rexR, rexX, rexB)
		if err != nil {
			return nil, err
		}
		rm := applySeg(mr.rm)
		reg := regOperand(mr.regField, rexPresent)
		accReg := regOperand(RegRAX, false) // AL/AX/EAX/RAX
		return finish(func(e *Engine) (bool, error) {
			dest, err := e.readOperand(rm, w)
			if err != nil {
				return false, err
			}
			acc, err := e.readOperand(accReg, w)
			if err != nil {
				return false, err
			}
			src, err := e.readOperand(reg, w)
			if err != nil {
				return false, err
			}
			// Compare DEST and ACC
			e.subWithFlags(dest, acc, w)
			
			// Equality check must be based on truncated values.
			// e.readOperand masks already, but let's be safe.
			dest &= maskWidth(w)
			acc &= maskWidth(w)
			if dest == acc {
				return false, e.writeOperand(rm, w, src)
			}
			return false, e.writeOperand(accReg, w, dest)
		})
	case op2 == 0xBC: // BSF r, r/m
		mr, err := decodeModRM(e, c, rexR, rexX, rexB)
		if err != nil {
			return nil, err
		}
		rm := applySeg(mr.rm)
		reg := regOperand(mr.regField, rexPresent)
		w := width(false)
		f3 := rep == repZ // F3 0F BC = TZCNT
		return finish(func(e *Engine) (bool, error) {
			v, err := e.readOperand(rm, w)
			if err != nil {
				return false, err
			}
			v &= maskWidth(w)
			if f3 { // TZCNT
				count := uint64(0)
				for count < uint64(w*8) && (v>>count)&1 == 0 {
					count++
				}
				e.setFlag(flagCF, v == 0)
				e.setFlag(flagZF, count == 0)
				return false, e.writeOperand(reg, w, count)
			}
			// BSF
			e.setFlag(flagZF, v == 0)
			if v == 0 {
				return false, nil
			}
			count := uint64(0)
			for (v>>count)&1 == 0 {
				count++
			}
			return false, e.writeOperand(reg, w, count)
		})
	case op2 == 0xBD: // BSR r, r/m  (or LZCNT with F3 prefix)
		mr, err := decodeModRM(e, c, rexR, rexX, rexB)
		if err != nil {
			return nil, err
		}
		rm := applySeg(mr.rm)
		reg := regOperand(mr.regField, rexPresent)
		w := width(false)
		f3 := rep == repZ
		return finish(func(e *Engine) (bool, error) {
			v, err := e.readOperand(rm, w)
			if err != nil {
				return false, err
			}
			v &= maskWidth(w)
			if f3 { // LZCNT
				bits := uint64(w * 8)
				count := uint64(0)
				for count < bits && (v>>(bits-1-count))&1 == 0 {
					count++
				}
				e.setFlag(flagCF, v == 0)
				e.setFlag(flagZF, count == 0)
				return false, e.writeOperand(reg, w, count)
			}
			// BSR
			e.setFlag(flagZF, v == 0)
			if v == 0 {
				return false, nil
			}
			bits := uint64(w * 8)
			count := bits - 1
			for (v>>count)&1 == 0 {
				count--
			}
			return false, e.writeOperand(reg, w, count)
		})
	case op2 == 0xB8 && rep == repZ: // POPCNT r, r/m (F3 0F B8)
		mr, err := decodeModRM(e, c, rexR, rexX, rexB)
		if err != nil {
			return nil, err
		}
		rm := applySeg(mr.rm)
		reg := regOperand(mr.regField, rexPresent)
		w := width(false)
		return finish(func(e *Engine) (bool, error) {
			v, err := e.readOperand(rm, w)
			if err != nil {
				return false, err
			}
			v &= maskWidth(w)
			cnt := uint64(0)
			for v != 0 {
				cnt += v & 1
				v >>= 1
			}
			e.setFlag(flagZF, cnt == 0)
			e.setFlag(flagCF, false)
			e.setFlag(flagOF, false)
			e.setFlag(flagSF, false)
			e.setFlag(flagAF, false)
			e.setFlag(flagPF, false)
			return false, e.writeOperand(reg, w, cnt)
		})

	// ── SSE/AVX via 0F prefix ─────────────────────────────────────────────
	// Dispatch based on rep / opSize16 to select the instruction variant.
	case op2 == 0x38: // 3-byte escape: 66 0F 38 xx (SSSE3/SSE4.1)
		return e.decodeThreeByte38(c, rexPresent, rexW, rexR, rexX, rexB, opSize16, applySeg, finish)

	case op2 == 0x3A: // 3-byte escape: 66 0F 3A xx (SSE4.1 imm8)
		return e.decodeThreeByte3A(c, rexPresent, rexW, rexR, rexX, rexB, opSize16, applySeg, finish)
	}

	// Remaining opcodes are all XMM.  Decode the ModRM byte and dispatch.
	d, err := e.decodeSSE0F(c, op2, rexPresent, rexW, rexR, rexX, rexB, opSize16, rep, applySeg, finish)
	if err == nil {
		return d, nil
	}
	return nil, fmt.Errorf("cpu: unsupported two-byte opcode 0F %#02x (66=%v F3=%v F2=%v): %v",
		op2, opSize16, rep == repZ, rep == repNZ, err)
}

// decodeSSE0F handles all XMM/YMM opcodes in the 0F xx space, selected
// by the rep/opSize16 flags that encode the mandatory prefix context.
func (e *Engine) decodeSSE0F(
	c *cursor,
	op2 byte,
	rexPresent, rexW, rexR, rexX, rexB, opSize16 bool,
	rep repKind,
	applySeg func(operand) operand,
	finish func(func(*Engine) (bool, error)) (*decoded, error),
) (*decoded, error) {
	// Helper: decode ModRM and return (xmmDst operand, xmmSrc operand, regField).
	decodeMR := func() (dst, src operand, rf int, err error) {
		mr, err := decodeModRM(e, c, rexR, rexX, rexB)
		if err != nil {
			return operand{}, operand{}, 0, err
		}
		rm := applySeg(mr.rm)
		reg := operand{kind: opndReg, reg: mr.regField}
		return reg, rm, mr.regField, nil
	}
	decodeMR2 := func() (xmmDst operand, xmmSrc operand, err error) {
		d, s, _, e2 := decodeMR()
		return d, s, e2
	}

	isSS := rep == repZ   // F3 0F: scalar single
	isSD := rep == repNZ  // F2 0F: scalar double
	isPD := opSize16      // 66 0F: packed double / SSE2 int

	// SSE2 integer ops require 66 prefix.
	sseInt := isPD

	// zeroUpper is always false for non-VEX SSE.
	const zu = false

	switch op2 {
	// ── Data movement ──────────────────────────────────────────────────

	case 0x10: // MOVUPS/MOVSS/MOVSD/MOVUPD xmm, xmm/m
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			if isSS { // MOVSS: merge upper 3 lanes from dst if mem src
				slo, shi, err := e.readXMMOp(src)
				if err != nil {
					return false, err
				}
				_ = shi
				dlo, dhi, _ := e.readXMMOp(dst)
				if src.kind == opndMem {
					return false, e.writeXMMOp(dst, slo&0xFFFFFFFF, dhi, zu)
				}
				return false, e.writeXMMOp(dst, (dlo&^uint64(0xFFFFFFFF))|(slo&0xFFFFFFFF), dhi, zu)
			}
			if isSD { // MOVSD: merge upper lane from dst if mem src
				slo, _, err := e.readXMMOp(src)
				if err != nil {
					return false, err
				}
				_, dhi, _ := e.readXMMOp(dst)
				if src.kind == opndMem {
					return false, e.writeXMMOp(dst, slo, dhi, zu)
				}
				return false, e.writeXMMOp(dst, slo, dhi, zu)
			}
			// MOVUPS / MOVUPD: full 128-bit copy.
			return false, e.execXMM(dst, src, zu, func(_, _, slo, shi uint64) (uint64, uint64) { return slo, shi })
		})

	case 0x11: // MOVUPS/MOVSS/MOVSD/MOVUPD xmm/m, xmm  (store direction)
		src, dst, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			if isSS {
				slo, _, _ := e.readXMMOp(src)
				dlo, dhi, _ := e.readXMMOp(dst)
				if dst.kind == opndMem {
					// Store only low 32 bits to m32.
					addr := e.effAddr(dst)
					return false, e.mem.writeChecked(addr, u64ToLE(slo&0xFFFFFFFF, 4), ProtWrite)
				}
				return false, e.writeXMMOp(dst, (dlo&^uint64(0xFFFFFFFF))|(slo&0xFFFFFFFF), dhi, zu)
			}
			if isSD {
				slo, _, _ := e.readXMMOp(src)
				_, dhi, _ := e.readXMMOp(dst)
				if dst.kind == opndMem {
					addr := e.effAddr(dst)
					return false, e.mem.writeChecked(addr, u64ToLE(slo, 8), ProtWrite)
				}
				return false, e.writeXMMOp(dst, slo, dhi, zu)
			}
			return false, e.execXMM(dst, src, zu, func(_, _, slo, shi uint64) (uint64, uint64) { return slo, shi })
		})

	case 0x12: // MOVLPS xmm, m64  /  MOVLPD xmm, m64
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			addr := e.effAddr(src)
			buf, err := e.mem.readChecked(addr, 8, ProtRead)
			if err != nil {
				return false, err
			}
			_, dhi, _ := e.readXMMOp(dst)
			return false, e.writeXMMOp(dst, leToU64(buf), dhi, zu)
		})

	case 0x13: // MOVLPS m64, xmm  /  MOVLPD m64, xmm
		src, dst, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			slo, _, _ := e.readXMMOp(src)
			addr := e.effAddr(dst)
			return false, e.mem.writeChecked(addr, u64ToLE(slo, 8), ProtWrite)
		})

	case 0x14: // UNPCKLPS / UNPCKLPD
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			dlo, _, _ := e.readXMMOp(dst)
			slo, _, _ := e.readXMMOp(src)
			if isPD {
				return false, e.writeXMMOp(dst, dlo, slo, zu)
			}
			// UNPCKLPS
			lo := (dlo & 0xFFFFFFFF) | (slo&0xFFFFFFFF)<<32
			hi := (dlo >> 32 & 0xFFFFFFFF) | (slo>>32&0xFFFFFFFF)<<32
			return false, e.writeXMMOp(dst, lo, hi, zu)
		})

	case 0x15: // UNPCKHPS / UNPCKHPD
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			_, dhi, _ := e.readXMMOp(dst)
			_, shi, _ := e.readXMMOp(src)
			if isPD {
				return false, e.writeXMMOp(dst, dhi, shi, zu)
			}
			lo := (dhi & 0xFFFFFFFF) | (shi&0xFFFFFFFF)<<32
			hi := (dhi >> 32 & 0xFFFFFFFF) | (shi>>32&0xFFFFFFFF)<<32
			return false, e.writeXMMOp(dst, lo, hi, zu)
		})

	case 0x16: // MOVHPS xmm, m64  /  MOVHPD xmm, m64
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			addr := e.effAddr(src)
			buf, err := e.mem.readChecked(addr, 8, ProtRead)
			if err != nil {
				return false, err
			}
			dlo, _, _ := e.readXMMOp(dst)
			return false, e.writeXMMOp(dst, dlo, leToU64(buf), zu)
		})

	case 0x17: // MOVHPS m64, xmm  /  MOVHPD m64, xmm
		src, dst, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			_, shi, _ := e.readXMMOp(src)
			addr := e.effAddr(dst)
			return false, e.mem.writeChecked(addr, u64ToLE(shi, 8), ProtWrite)
		})

	case 0x28: // MOVAPS xmm,xmm/m128  /  MOVAPD xmm,xmm/m128
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, func(_, _, slo, shi uint64) (uint64, uint64) { return slo, shi })
		})

	case 0x29: // MOVAPS xmm/m128,xmm  /  MOVAPD
		src, dst, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, func(_, _, slo, shi uint64) (uint64, uint64) { return slo, shi })
		})

	case 0x2A: // CVTSI2SS / CVTSI2SD
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		w := 4
		if rexW {
			w = 8
		}
		return finish(func(e *Engine) (bool, error) {
			iv, err := e.readOperand(src, w)
			if err != nil {
				return false, err
			}
			intVal := int64(signExtend(iv, w*8))
			dlo, dhi, _ := e.readXMMOp(dst)
			var rlo, rhi uint64
			if isSS {
				rlo, rhi = sseCvtsi2ss(dlo, dhi, intVal)
			} else { // isSD
				rlo, rhi = sseCvtsi2sd(dlo, dhi, intVal)
			}
			return false, e.writeXMMOp(dst, rlo, rhi, zu)
		})

	case 0x2C: // CVTTSS2SI / CVTTSD2SI
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		w := 4
		if rexW {
			w = 8
		}
		return finish(func(e *Engine) (bool, error) {
			slo, _, err := e.readXMMOp(src)
			if err != nil {
				return false, err
			}
			var iv int64
			if isSS {
				iv = sseCvttss2si(slo)
			} else {
				iv = sseCvttsd2si(slo)
			}
			return false, e.writeOperand(dst, w, uint64(iv))
		})

	case 0x2D: // CVTSS2SI / CVTSD2SI (round-to-nearest)
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		w := 4
		if rexW {
			w = 8
		}
		return finish(func(e *Engine) (bool, error) {
			slo, _, err := e.readXMMOp(src)
			if err != nil {
				return false, err
			}
			var iv int64
			if isSS {
				iv = sseCvtss2si(slo)
			} else {
				iv = sseCvtsd2si(slo)
			}
			return false, e.writeOperand(dst, w, uint64(iv))
		})

	case 0x2E: // UCOMISS / UCOMISD
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			dlo, _, _ := e.readXMMOp(dst)
			slo, _, err := e.readXMMOp(src)
			if err != nil {
				return false, err
			}
			if isPD {
				e.sseComisd(dlo, slo)
			} else {
				e.sseComiss(dlo, slo)
			}
			return false, nil
		})

	case 0x2F: // COMISS / COMISD
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			dlo, _, _ := e.readXMMOp(dst)
			slo, _, err := e.readXMMOp(src)
			if err != nil {
				return false, err
			}
			if isPD {
				e.sseComisd(dlo, slo)
			} else {
				e.sseComiss(dlo, slo)
			}
			return false, nil
		})

	case 0x50: // MOVMSKPS / MOVMSKPD
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			slo, shi, _ := e.readXMMOp(src)
			var mask uint32
			if isPD {
				mask = sseMovmskpd(slo, shi)
			} else {
				mask = sseMovmskps(slo, shi)
			}
			return false, e.writeOperand(dst, 4, uint64(mask))
		})

	// ── Packed float / double arithmetic ───────────────────────────────

	case 0x51: // SQRTPS / SQRTPD / SQRTSS / SQRTSD
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			slo, shi, err := e.readXMMOp(src)
			if err != nil {
				return false, err
			}
			dlo, dhi, _ := e.readXMMOp(dst)
			var rlo, rhi uint64
			switch {
			case isSS:
				rlo, rhi = sseSqrtss(dlo, dhi, slo)
			case isSD:
				rlo, rhi = sseSqrtsd(slo, dhi, 0)
			case isPD:
				rlo, rhi = e.sseSqrtpd(slo, shi)
			default:
				rlo, rhi = e.sseSqrtps(slo, shi)
			}
			return false, e.writeXMMOp(dst, rlo, rhi, zu)
		})

	case 0x52: // RSQRTPS / RSQRTSS
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			slo, shi, err := e.readXMMOp(src)
			if err != nil {
				return false, err
			}
			dlo, dhi, _ := e.readXMMOp(dst)
			var rlo, rhi uint64
			if isSS {
				rlo, rhi = sseRsqrtss(dlo, dhi, slo)
			} else {
				rlo, rhi = e.sseRsqrtps(slo, shi)
			}
			return false, e.writeXMMOp(dst, rlo, rhi, zu)
		})

	case 0x53: // RCPPS / RCPSS
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			slo, shi, err := e.readXMMOp(src)
			if err != nil {
				return false, err
			}
			dlo, dhi, _ := e.readXMMOp(dst)
			var rlo, rhi uint64
			if isSS {
				rlo, rhi = sseRcpss(dlo, dhi, slo)
			} else {
				rlo, rhi = e.sseRcpps(slo, shi)
			}
			return false, e.writeXMMOp(dst, rlo, rhi, zu)
		})

	case 0x54: // ANDPS / ANDPD
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, e.sseAndps)
		})

	case 0x55: // ANDNPS / ANDNPD
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, e.sseAndnps)
		})

	case 0x56: // ORPS / ORPD
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, e.sseOrps)
		})

	case 0x57: // XORPS / XORPD
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, e.sseXorps)
		})

	case 0x58: // ADDPS/PD/SS/SD
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			slo, shi, err := e.readXMMOp(src)
			if err != nil {
				return false, err
			}
			dlo, dhi, _ := e.readXMMOp(dst)
			var rlo, rhi uint64
			switch {
			case isSS:
				rlo, rhi = sseAddss(dlo, dhi, slo, shi)
			case isSD:
				rlo, rhi = sseAddsd(dlo, dhi, slo, shi)
			case isPD:
				rlo, rhi = e.sseAddpd(dlo, dhi, slo, shi)
			default:
				rlo, rhi = e.sseAddps(dlo, dhi, slo, shi)
			}
			return false, e.writeXMMOp(dst, rlo, rhi, zu)
		})

	case 0x59: // MULPS/PD/SS/SD
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			slo, shi, err := e.readXMMOp(src)
			if err != nil {
				return false, err
			}
			dlo, dhi, _ := e.readXMMOp(dst)
			var rlo, rhi uint64
			switch {
			case isSS:
				rlo, rhi = sseMulss(dlo, dhi, slo, shi)
			case isSD:
				rlo, rhi = sseMulsd(dlo, dhi, slo, shi)
			case isPD:
				rlo, rhi = e.sseMulpd(dlo, dhi, slo, shi)
			default:
				rlo, rhi = e.sseMulps(dlo, dhi, slo, shi)
			}
			return false, e.writeXMMOp(dst, rlo, rhi, zu)
		})

	case 0x5A: // CVTPS2PD / CVTPD2PS / CVTSS2SD / CVTSD2SS
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			slo, shi, err := e.readXMMOp(src)
			if err != nil {
				return false, err
			}
			dlo, dhi, _ := e.readXMMOp(dst)
			var rlo, rhi uint64
			switch {
			case isSS:
				rlo, rhi = sseCvtss2sd(dlo, dhi, slo, shi)
			case isSD:
				rlo, rhi = sseCvtsd2ss(dlo, dhi, slo, shi)
			case isPD:
				rlo, rhi = sseCvtpd2ps(slo, shi)
			default:
				rlo, rhi = sseCvtps2pd(slo, shi)
			}
			return false, e.writeXMMOp(dst, rlo, rhi, zu)
		})

	case 0x5B: // CVTDQ2PS (NP) / CVTPS2DQ (66) / CVTTPS2DQ (F3)
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			slo, shi, err := e.readXMMOp(src)
			if err != nil {
				return false, err
			}
			var rlo, rhi uint64
			switch {
			case isSS:
				rlo, rhi = sseCvttps2dq(slo, shi)
			case isPD:
				rlo, rhi = sseCvtps2dq(slo, shi)
			default:
				rlo, rhi = sseCvtdq2ps(slo, shi)
			}
			return false, e.writeXMMOp(dst, rlo, rhi, zu)
		})

	case 0x5C: // SUBPS/PD/SS/SD
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			slo, shi, err := e.readXMMOp(src)
			if err != nil {
				return false, err
			}
			dlo, dhi, _ := e.readXMMOp(dst)
			var rlo, rhi uint64
			switch {
			case isSS:
				rlo, rhi = sseSubss(dlo, dhi, slo, shi)
			case isSD:
				rlo, rhi = sseSubsd(dlo, dhi, slo, shi)
			case isPD:
				rlo, rhi = e.sseSubpd(dlo, dhi, slo, shi)
			default:
				rlo, rhi = e.sseSubps(dlo, dhi, slo, shi)
			}
			return false, e.writeXMMOp(dst, rlo, rhi, zu)
		})

	case 0x5D: // MINPS/PD/SS/SD
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			slo, shi, err := e.readXMMOp(src)
			if err != nil {
				return false, err
			}
			dlo, dhi, _ := e.readXMMOp(dst)
			var rlo, rhi uint64
			switch {
			case isSS:
				rlo, rhi = sseMinss(dlo, dhi, slo, shi)
			case isSD:
				rlo, rhi = sseMinsd(dlo, dhi, slo, shi)
			case isPD:
				rlo, rhi = e.sseMinpd(dlo, dhi, slo, shi)
			default:
				rlo, rhi = e.sseMinps(dlo, dhi, slo, shi)
			}
			return false, e.writeXMMOp(dst, rlo, rhi, zu)
		})

	case 0x5E: // DIVPS/PD/SS/SD
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			slo, shi, err := e.readXMMOp(src)
			if err != nil {
				return false, err
			}
			dlo, dhi, _ := e.readXMMOp(dst)
			var rlo, rhi uint64
			switch {
			case isSS:
				rlo, rhi = sseDivss(dlo, dhi, slo, shi)
			case isSD:
				rlo, rhi = sseDivsd(dlo, dhi, slo, shi)
			case isPD:
				rlo, rhi = e.sseDivpd(dlo, dhi, slo, shi)
			default:
				rlo, rhi = e.sseDivps(dlo, dhi, slo, shi)
			}
			return false, e.writeXMMOp(dst, rlo, rhi, zu)
		})

	case 0x5F: // MAXPS/PD/SS/SD
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			slo, shi, err := e.readXMMOp(src)
			if err != nil {
				return false, err
			}
			dlo, dhi, _ := e.readXMMOp(dst)
			var rlo, rhi uint64
			switch {
			case isSS:
				rlo, rhi = sseMaxss(dlo, dhi, slo, shi)
			case isSD:
				rlo, rhi = sseMaxsd(dlo, dhi, slo, shi)
			case isPD:
				rlo, rhi = e.sseMaxpd(dlo, dhi, slo, shi)
			default:
				rlo, rhi = e.sseMaxps(dlo, dhi, slo, shi)
			}
			return false, e.writeXMMOp(dst, rlo, rhi, zu)
		})

	// ── SSE2 integer packed ops (require 66 prefix) ────────────────────

	case 0x60: // PUNPCKLBW
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, func(dlo, dhi, slo, shi uint64) (uint64, uint64) {
				return ssePunpcklbw(dlo, dhi, slo, shi)
			})
		})
	case 0x61: // PUNPCKLWD
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, func(dlo, dhi, slo, shi uint64) (uint64, uint64) {
				return ssePunpcklwd(dlo, dhi, slo, shi)
			})
		})
	case 0x62: // PUNPCKLDQ
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, func(dlo, dhi, slo, shi uint64) (uint64, uint64) {
				return ssePunpckldq(dlo, dhi, slo, shi)
			})
		})
	case 0x63: // PACKSSWB
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, ssePacksswb)
		})
	case 0x64: // PCMPGTB
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, e.ssePcmpgtb)
		})
	case 0x65: // PCMPGTW
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, e.ssePcmpgtw)
		})
	case 0x66: // PCMPGTD
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, e.ssePcmpgtd)
		})
	case 0x67: // PACKUSWB
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, ssePackuswb)
		})
	case 0x68: // PUNPCKHBW
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, func(dlo, dhi, slo, shi uint64) (uint64, uint64) {
				return ssePunpckhbw(dlo, dhi, slo, shi)
			})
		})
	case 0x69: // PUNPCKHWD
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, func(dlo, dhi, slo, shi uint64) (uint64, uint64) {
				return ssePunpckhwd(dlo, dhi, slo, shi)
			})
		})
	case 0x6A: // PUNPCKHDQ
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, func(dlo, dhi, slo, shi uint64) (uint64, uint64) {
				return ssePunpckhdq(dlo, dhi, slo, shi)
			})
		})
	case 0x6B: // PACKSSDW
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, ssePackssdw)
		})
	case 0x6C: // PUNPCKLQDQ
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, func(dlo, dhi, slo, shi uint64) (uint64, uint64) {
				return ssePunpcklqdq(dlo, dhi, slo, shi)
			})
		})
	case 0x6D: // PUNPCKHQDQ
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, func(dlo, dhi, slo, shi uint64) (uint64, uint64) {
				return ssePunpckhqdq(dlo, dhi, slo, shi)
			})
		})

	case 0x6E: // 66: MOVD xmm,r/m32  (or MOVQ xmm,r/m64 with REX.W)
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		w := 4
		if rexW {
			w = 8
		}
		return finish(func(e *Engine) (bool, error) {
			v, err := e.readOperand(src, w)
			if err != nil {
				return false, err
			}
			return false, e.writeXMMOp(dst, v, 0, zu)
		})

	case 0x6F: // MOVDQA xmm,xmm/m128 (66) / MOVDQU xmm,xmm/m128 (F3)
		if !sseInt && !isSS {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, func(_, _, slo, shi uint64) (uint64, uint64) { return slo, shi })
		})

	case 0x70: // PSHUFD (66) / PSHUFHW (F3) / PSHUFLW (F2)
		dst, src, rf, err := decodeMR()
		if err != nil {
			return nil, err
		}
		_ = rf
		imm, err := c.u8()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			slo, shi, err := e.readXMMOp(src)
			if err != nil {
				return false, err
			}
			var rlo, rhi uint64
			switch {
			case isSS:
				rlo, rhi = ssePshufhw(slo, shi, imm)
			case isSD:
				rlo, rhi = ssePshuflw(slo, shi, imm)
			default:
				rlo, rhi = ssePshufd(slo, shi, imm)
			}
			return false, e.writeXMMOp(dst, rlo, rhi, zu)
		})

	case 0x71: // group 12: PSRLW /2, PSRAW /4, PSLLW /6  (66 prefix, imm8)
		if !sseInt {
			break
		}
		mr, err := decodeModRM(e, c, rexR, rexX, rexB)
		if err != nil {
			return nil, err
		}
		rm := operand{kind: opndReg, reg: mr.rm.reg}
		imm, err := c.u8()
		if err != nil {
			return nil, err
		}
		idx := mr.regField & 7
		return finish(func(e *Engine) (bool, error) {
			lo, hi, _ := e.readXMMOp(rm)
			var rlo, rhi uint64
			switch idx {
			case 2:
				rlo, rhi = ssePsrlw(lo, hi, uint64(imm))
			case 4:
				rlo, rhi = ssePsraw(lo, hi, uint64(imm))
			case 6:
				rlo, rhi = ssePsllw(lo, hi, uint64(imm))
			default:
				return false, fmt.Errorf("cpu: PSHIFT grp12 /%d undefined", idx)
			}
			return false, e.writeXMMOp(rm, rlo, rhi, zu)
		})

	case 0x72: // group 13: PSRLD /2, PSRAD /4, PSLLD /6
		if !sseInt {
			break
		}
		mr, err := decodeModRM(e, c, rexR, rexX, rexB)
		if err != nil {
			return nil, err
		}
		rm := operand{kind: opndReg, reg: mr.rm.reg}
		imm, err := c.u8()
		if err != nil {
			return nil, err
		}
		idx := mr.regField & 7
		return finish(func(e *Engine) (bool, error) {
			lo, hi, _ := e.readXMMOp(rm)
			var rlo, rhi uint64
			switch idx {
			case 2:
				rlo, rhi = ssePsrld(lo, hi, uint64(imm))
			case 4:
				rlo, rhi = ssePsrad(lo, hi, uint64(imm))
			case 6:
				rlo, rhi = ssePslld(lo, hi, uint64(imm))
			default:
				return false, fmt.Errorf("cpu: PSHIFT grp13 /%d undefined", idx)
			}
			return false, e.writeXMMOp(rm, rlo, rhi, zu)
		})

	case 0x73: // group 14: PSRLQ /2, PSRLDQ /3, PSLLQ /6, PSLLDQ /7
		if !sseInt {
			break
		}
		mr, err := decodeModRM(e, c, rexR, rexX, rexB)
		if err != nil {
			return nil, err
		}
		rm := operand{kind: opndReg, reg: mr.rm.reg}
		imm, err := c.u8()
		if err != nil {
			return nil, err
		}
		idx := mr.regField & 7
		return finish(func(e *Engine) (bool, error) {
			lo, hi, _ := e.readXMMOp(rm)
			var rlo, rhi uint64
			switch idx {
			case 2:
				rlo, rhi = ssePsrlq(lo, hi, uint64(imm))
			case 3:
				rlo, rhi = ssePsrldq(lo, hi, imm)
			case 6:
				rlo, rhi = ssePsllq(lo, hi, uint64(imm))
			case 7:
				rlo, rhi = ssePslldq(lo, hi, imm)
			default:
				return false, fmt.Errorf("cpu: PSHIFT grp14 /%d undefined", idx)
			}
			return false, e.writeXMMOp(rm, rlo, rhi, zu)
		})

	case 0x74: // PCMPEQB
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, e.ssePcmpeqb)
		})
	case 0x75: // PCMPEQW
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, e.ssePcmpeqw)
		})
	case 0x76: // PCMPEQD
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, e.ssePcmpeqd)
		})

	case 0x7C: // HADDPD (66) / HADDPS (F2)
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			slo, shi, err := e.readXMMOp(src)
			if err != nil {
				return false, err
			}
			dlo, dhi, _ := e.readXMMOp(dst)
			var rlo, rhi uint64
			if isPD {
				rlo, rhi = sseHaddpd(dlo, dhi, slo, shi)
			} else {
				rlo, rhi = sseHaddps(dlo, dhi, slo, shi)
			}
			return false, e.writeXMMOp(dst, rlo, rhi, zu)
		})

	case 0x7E: // 66: MOVD r/m32,xmm  (or MOVQ r/m64,xmm with REX.W)
		//        F3: MOVQ xmm,xmm/m64
		if isSS { // MOVQ xmm, xmm/m64
			dst, src, err := decodeMR2()
			if err != nil {
				return nil, err
			}
			return finish(func(e *Engine) (bool, error) {
				slo, _, err := e.readXMMOp(src)
				if err != nil {
					return false, err
				}
				return false, e.writeXMMOp(dst, slo, 0, zu)
			})
		}
		if !sseInt {
			break
		}
		src, dst, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		w := 4
		if rexW {
			w = 8
		}
		return finish(func(e *Engine) (bool, error) {
			slo, _, _ := e.readXMMOp(src)
			return false, e.writeOperand(dst, w, slo)
		})

	case 0x7F: // MOVDQA xmm/m128,xmm (66) / MOVDQU xmm/m128,xmm (F3)
		if !sseInt && !isSS {
			break
		}
		src, dst, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, func(_, _, slo, shi uint64) (uint64, uint64) { return slo, shi })
		})

	case 0xAE: // group 15: LDMXCSR /2  STMXCSR /3
		mr, err := decodeModRM(e, c, rexR, rexX, rexB)
		if err != nil {
			return nil, err
		}
		rm := applySeg(mr.rm)
		idx := mr.regField & 7
		return finish(func(e *Engine) (bool, error) {
			switch idx {
			case 2: // LDMXCSR m32
				v, err := e.readOperand(rm, 4)
				if err != nil {
					return false, err
				}
				e.regs.mxcsr = uint32(v)
			case 3: // STMXCSR m32
				if err := e.writeOperand(rm, 4, uint64(e.regs.mxcsr)); err != nil {
					return false, err
				}
			case 7: // SFENCE (NOP here)
			default:
				return false, fmt.Errorf("cpu: 0F AE /%d not implemented", idx)
			}
			return false, nil
		})

	case 0xC2: // CMPPS/PD/SS/SD xmm, xmm/m, imm8
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		imm, err := c.u8()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			slo, shi, err := e.readXMMOp(src)
			if err != nil {
				return false, err
			}
			dlo, dhi, _ := e.readXMMOp(dst)
			var rlo, rhi uint64
			switch {
			case isSS:
				rlo, rhi = sseCmpss(dlo, dhi, slo, shi, imm)
			case isSD:
				rlo, rhi = sseCmpsd(dlo, dhi, slo, shi, imm)
			case isPD:
				rlo, rhi = e.sseCmppd(dlo, dhi, slo, shi, imm)
			default:
				rlo, rhi = e.sseCmpps(dlo, dhi, slo, shi, imm)
			}
			return false, e.writeXMMOp(dst, rlo, rhi, zu)
		})

	case 0xC4: // PINSRW xmm, r/m16, imm8
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		imm, err := c.u8()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			v, err := e.readOperand(src, 2)
			if err != nil {
				return false, err
			}
			dlo, dhi, _ := e.readXMMOp(dst)
			rlo, rhi := ssePinsrw(dlo, dhi, uint16(v), imm)
			return false, e.writeXMMOp(dst, rlo, rhi, zu)
		})

	case 0xC5: // PEXTRW r, xmm, imm8
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		imm, err := c.u8()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			slo, shi, _ := e.readXMMOp(src)
			v := ssePextrw(slo, shi, imm)
			return false, e.writeOperand(dst, 4, uint64(v))
		})

	case 0xC6: // SHUFPS / SHUFPD
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		imm, err := c.u8()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			slo, shi, err := e.readXMMOp(src)
			if err != nil {
				return false, err
			}
			dlo, dhi, _ := e.readXMMOp(dst)
			var rlo, rhi uint64
			if isPD {
				rlo, rhi = sseShufpd(dlo, dhi, slo, shi, imm)
			} else {
				rlo, rhi = sseShufps(dlo, dhi, slo, shi, imm)
			}
			return false, e.writeXMMOp(dst, rlo, rhi, zu)
		})

	case 0xD1: // PSRLW xmm, xmm/m128
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			slo, _, err := e.readXMMOp(src)
			if err != nil {
				return false, err
			}
			dlo, dhi, _ := e.readXMMOp(dst)
			rlo, rhi := ssePsrlw(dlo, dhi, slo&0xFF)
			return false, e.writeXMMOp(dst, rlo, rhi, zu)
		})
	case 0xD2: // PSRLD
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			slo, _, err := e.readXMMOp(src)
			if err != nil {
				return false, err
			}
			dlo, dhi, _ := e.readXMMOp(dst)
			rlo, rhi := ssePsrld(dlo, dhi, slo&0xFF)
			return false, e.writeXMMOp(dst, rlo, rhi, zu)
		})
	case 0xD3: // PSRLQ
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			slo, _, err := e.readXMMOp(src)
			if err != nil {
				return false, err
			}
			dlo, dhi, _ := e.readXMMOp(dst)
			rlo, rhi := ssePsrlq(dlo, dhi, slo&0xFF)
			return false, e.writeXMMOp(dst, rlo, rhi, zu)
		})
	case 0xD4: // PADDQ
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, e.ssePaddq)
		})
	case 0xD5: // PMULLW
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, e.ssePmullw)
		})
	case 0xD6: // MOVQ xmm/m64, xmm  (66 0F D6)
		if !sseInt {
			break
		}
		src, dst, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			slo, _, _ := e.readXMMOp(src)
			if dst.kind == opndMem {
				addr := e.effAddr(dst)
				return false, e.mem.writeChecked(addr, u64ToLE(slo, 8), ProtWrite)
			}
			return false, e.writeXMMOp(dst, slo, 0, zu)
		})
	case 0xD7: // PMOVMSKB r, xmm
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			slo, shi, _ := e.readXMMOp(src)
			return false, e.writeOperand(dst, 4, uint64(ssePmovmskb(slo, shi)))
		})
	case 0xD8: // PSUBUSB
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, e.ssePsubusb)
		})
	case 0xD9: // PSUBUSW
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, e.ssePsubusw)
		})
	case 0xDA: // PMINUB
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, e.ssePminub)
		})
	case 0xDB: // PAND
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, e.ssePand)
		})
	case 0xDC: // PADDUSB
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, e.ssePaddusb)
		})
	case 0xDD: // PADDUSW
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, e.ssePaddusw)
		})
	case 0xDE: // PMAXUB
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, e.ssePmaxub)
		})
	case 0xDF: // PANDN
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, e.ssePandn)
		})
	case 0xE0: // PAVGB
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, e.ssePavgb)
		})
	case 0xE1: // PSRAW
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			slo, _, err := e.readXMMOp(src)
			if err != nil {
				return false, err
			}
			dlo, dhi, _ := e.readXMMOp(dst)
			rlo, rhi := ssePsraw(dlo, dhi, slo&0xFF)
			return false, e.writeXMMOp(dst, rlo, rhi, zu)
		})
	case 0xE2: // PSRAD
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			slo, _, err := e.readXMMOp(src)
			if err != nil {
				return false, err
			}
			dlo, dhi, _ := e.readXMMOp(dst)
			rlo, rhi := ssePsrad(dlo, dhi, slo&0xFF)
			return false, e.writeXMMOp(dst, rlo, rhi, zu)
		})
	case 0xE3: // PAVGW
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, e.ssePavgw)
		})
	case 0xE4: // PMULHUW
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, e.ssePmulhuw)
		})
	case 0xE5: // PMULHW
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, e.ssePmulhw)
		})
	case 0xE6: // CVTTPD2DQ (66) / CVTDQ2PD (F3) / CVTPD2DQ (F2)
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			slo, shi, err := e.readXMMOp(src)
			if err != nil {
				return false, err
			}
			var rlo, rhi uint64
			switch {
			case isSS:
				rlo, rhi = sseCvtdq2pd(slo, shi)
			case isSD:
				rlo, rhi = sseCvtpd2dq(slo, shi)
			default: // isPD
				rlo, rhi = sseCvttpd2dq(slo, shi)
			}
			return false, e.writeXMMOp(dst, rlo, rhi, zu)
		})
	case 0xE7: // MOVNTDQ m128, xmm  (66)
		if !sseInt {
			break
		}
		src, dst, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			slo, shi, _ := e.readXMMOp(src)
			addr := e.effAddr(dst)
			buf := make([]byte, 16)
			copy(buf[:8], u64ToLE(slo, 8))
			copy(buf[8:], u64ToLE(shi, 8))
			return false, e.mem.writeChecked(addr, buf, ProtWrite)
		})
	case 0xE8: // PSUBSB
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, e.ssePsubsb)
		})
	case 0xE9: // PSUBSW
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, e.ssePsubsw)
		})
	case 0xEA: // PMINSW
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, e.ssePminsw)
		})
	case 0xEB: // POR
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, e.ssePor)
		})
	case 0xEC: // PADDSB
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, e.ssePaddsb)
		})
	case 0xED: // PADDSW
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, e.ssePaddsw)
		})
	case 0xEE: // PMAXSW
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, e.ssePmaxsw)
		})
	case 0xEF: // PXOR
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, e.ssePxor)
		})
	case 0xF1: // PSLLW
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			slo, _, err := e.readXMMOp(src)
			if err != nil {
				return false, err
			}
			dlo, dhi, _ := e.readXMMOp(dst)
			rlo, rhi := ssePsllw(dlo, dhi, slo&0xFF)
			return false, e.writeXMMOp(dst, rlo, rhi, zu)
		})
	case 0xF2: // PSLLD
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			slo, _, err := e.readXMMOp(src)
			if err != nil {
				return false, err
			}
			dlo, dhi, _ := e.readXMMOp(dst)
			rlo, rhi := ssePslld(dlo, dhi, slo&0xFF)
			return false, e.writeXMMOp(dst, rlo, rhi, zu)
		})
	case 0xF3: // PSLLQ
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			slo, _, err := e.readXMMOp(src)
			if err != nil {
				return false, err
			}
			dlo, dhi, _ := e.readXMMOp(dst)
			rlo, rhi := ssePsllq(dlo, dhi, slo&0xFF)
			return false, e.writeXMMOp(dst, rlo, rhi, zu)
		})
	case 0xF4: // PMULUDQ
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, e.ssePmuludq)
		})
	case 0xF5: // PMADDWD
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, e.ssePmaddwd)
		})
	case 0xF6: // PSADBW
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, e.ssePsadbw)
		})
	case 0xF8: // PSUBB
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, e.ssePsubb)
		})
	case 0xF9: // PSUBW
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, e.ssePsubw)
		})
	case 0xFA: // PSUBD
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, e.ssePsubd)
		})
	case 0xFB: // PSUBQ
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, e.ssePsubq)
		})
	case 0xFC: // PADDB
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, e.ssePaddb)
		})
	case 0xFD: // PADDW
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, e.ssePaddw)
		})
	case 0xFE: // PADDD
		if !sseInt {
			break
		}
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, e.ssePaddd)
		})
	}

	return nil, fmt.Errorf("cpu: SSE 0F %#02x (66=%v F3=%v F2=%v) not implemented",
		op2, isPD, isSS, isSD)
}

// decodeThreeByte38 handles 66 0F 38 xx opcodes (SSSE3 / SSE4.1).
func (e *Engine) decodeThreeByte38(
	c *cursor,
	rexPresent, rexW, rexR, rexX, rexB, opSize16 bool,
	applySeg func(operand) operand,
	finish func(func(*Engine) (bool, error)) (*decoded, error),
) (*decoded, error) {
	op3, err := c.u8()
	if err != nil {
		return nil, err
	}

	decodeMR2 := func() (dst, src operand, err error) {
		mr, err := decodeModRM(e, c, rexR, rexX, rexB)
		if err != nil {
			return operand{}, operand{}, err
		}
		rm := applySeg(mr.rm)
		reg := operand{kind: opndReg, reg: mr.regField}
		return reg, rm, nil
	}
	const zu = false

	switch op3 {
	case 0x00: // PSHUFB xmm, xmm/m128
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			slo, shi, err := e.readXMMOp(src)
			if err != nil {
				return false, err
			}
			dlo, dhi, _ := e.readXMMOp(dst)
			rlo, rhi := ssePshufb(dlo, dhi, slo, shi)
			return false, e.writeXMMOp(dst, rlo, rhi, zu)
		})
	case 0x04: // PMADDUBSW
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			slo, shi, err := e.readXMMOp(src)
			if err != nil {
				return false, err
			}
			dlo, dhi, _ := e.readXMMOp(dst)
			// Each pair: signed byte from src * unsigned byte from dst, saturated sum.
			pmaddubsw := func(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
				return lane16(dlo, dhi, slo, shi, func(d, s uint16) uint16 {
					// d = two unsigned bytes, s = two signed bytes
					d0 := int16(int8(s & 0xFF))
					d1 := int16(int8(s >> 8))
					s0 := int16(d & 0xFF)
					s1 := int16(d >> 8)
					r := int32(d0)*int32(s0) + int32(d1)*int32(s1)
					if r > 32767 {
						return 32767
					}
					if r < -32768 {
						return 0x8000
					}
					return uint16(int16(r))
				})
			}
			rlo, rhi := pmaddubsw(dlo, dhi, slo, shi)
			return false, e.writeXMMOp(dst, rlo, rhi, zu)
		})
	case 0x17: // PTEST xmm, xmm/m128
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			slo, shi, err := e.readXMMOp(src)
			if err != nil {
				return false, err
			}
			dlo, dhi, _ := e.readXMMOp(dst)
			e.ssePtest(dlo, dhi, slo, shi)
			return false, nil
		})
	case 0x28: // PMULDQ xmm, xmm/m128
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, e.ssePmuldq)
		})
	case 0x29: // PCMPEQQ
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, e.ssePcmpeqq)
		})
	case 0x37: // PCMPGTQ (SSE4.2)
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, e.ssePcmpgtq)
		})
	case 0x38: // PMINSB
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, e.ssePminsb)
		})
	case 0x39: // PMINSD
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, e.ssePminsd)
		})
	case 0x3A: // PMINUW
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, e.ssePminuw)
		})
	case 0x3B: // PMINUD
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, e.ssePminud)
		})
	case 0x3C: // PMAXSB
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, e.ssePmaxsb)
		})
	case 0x3D: // PMAXSD
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, e.ssePmaxsd)
		})
	case 0x3E: // PMAXUW
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, e.ssePmaxuw)
		})
	case 0x3F: // PMAXUD
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, e.ssePmaxud)
		})
	case 0x40: // PMULLD (SSE4.1)
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.execXMM(dst, src, zu, e.ssePmulld)
		})
	}
	return nil, fmt.Errorf("cpu: unsupported 0F 38 %#02x", op3)
}

// decodeThreeByte3A handles 66 0F 3A xx opcodes (SSE4.1 immediate ops).
func (e *Engine) decodeThreeByte3A(
	c *cursor,
	rexPresent, rexW, rexR, rexX, rexB, opSize16 bool,
	applySeg func(operand) operand,
	finish func(func(*Engine) (bool, error)) (*decoded, error),
) (*decoded, error) {
	op3, err := c.u8()
	if err != nil {
		return nil, err
	}

	decodeMR2 := func() (dst, src operand, err error) {
		mr, err := decodeModRM(e, c, rexR, rexX, rexB)
		if err != nil {
			return operand{}, operand{}, err
		}
		rm := applySeg(mr.rm)
		reg := operand{kind: opndReg, reg: mr.regField}
		return reg, rm, nil
	}
	const zu = false

	switch op3 {
	case 0x08: // ROUNDPS xmm, xmm/m128, imm8
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		imm, err := c.u8()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			slo, shi, err := e.readXMMOp(src)
			if err != nil {
				return false, err
			}
			rlo, rhi := sseRoundps(slo, shi, imm)
			return false, e.writeXMMOp(dst, rlo, rhi, zu)
		})
	case 0x09: // ROUNDPD
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		imm, err := c.u8()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			slo, shi, err := e.readXMMOp(src)
			if err != nil {
				return false, err
			}
			rlo, rhi := sseRoundpd(slo, shi, imm)
			return false, e.writeXMMOp(dst, rlo, rhi, zu)
		})
	case 0x0A: // ROUNDSS xmm, xmm/m32, imm8
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		imm, err := c.u8()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			slo, _, err := e.readXMMOp(src)
			if err != nil {
				return false, err
			}
			dlo, dhi, _ := e.readXMMOp(dst)
			rlo, rhi := sseRoundss(slo, dhi, imm)
			_ = dlo
			return false, e.writeXMMOp(dst, rlo, rhi, zu)
		})
	case 0x0B: // ROUNDSD xmm, xmm/m64, imm8
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		imm, err := c.u8()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			slo, _, err := e.readXMMOp(src)
			if err != nil {
				return false, err
			}
			_, dhi, _ := e.readXMMOp(dst)
			rlo, rhi := sseRoundsd(slo, dhi, imm)
			return false, e.writeXMMOp(dst, rlo, rhi, zu)
		})
	case 0x0F: // PALIGNR xmm, xmm/m128, imm8
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		imm, err := c.u8()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			slo, shi, err := e.readXMMOp(src)
			if err != nil {
				return false, err
			}
			dlo, dhi, _ := e.readXMMOp(dst)
			rlo, rhi := ssePalignr(dlo, dhi, slo, shi, imm)
			return false, e.writeXMMOp(dst, rlo, rhi, zu)
		})
	case 0x14: // PEXTRB r/m8, xmm, imm8
		src, dst, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		imm, err := c.u8()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			slo, shi, _ := e.readXMMOp(src)
			v := ssePextrb(slo, shi, imm)
			return false, e.writeOperand(dst, 4, uint64(v))
		})
	case 0x15: // PEXTRW r/m16, xmm, imm8
		src, dst, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		imm, err := c.u8()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			slo, shi, _ := e.readXMMOp(src)
			v := ssePextrw(slo, shi, imm)
			return false, e.writeOperand(dst, 4, uint64(v))
		})
	case 0x16: // PEXTRD r/m32, xmm, imm8  (or PEXTRQ with REX.W)
		src, dst, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		imm, err := c.u8()
		if err != nil {
			return nil, err
		}
		w := 4
		if rexW {
			w = 8
		}
		return finish(func(e *Engine) (bool, error) {
			slo, shi, _ := e.readXMMOp(src)
			var v uint64
			if w == 8 {
				v = ssePextrq(slo, shi, imm)
			} else {
				v = uint64(ssePextrd(slo, shi, imm))
			}
			return false, e.writeOperand(dst, w, v)
		})
	case 0x20: // PINSRB xmm, r/m8, imm8
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		imm, err := c.u8()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			v, err := e.readOperand(src, 4)
			if err != nil {
				return false, err
			}
			dlo, dhi, _ := e.readXMMOp(dst)
			rlo, rhi := ssePinsrb(dlo, dhi, uint8(v), imm)
			return false, e.writeXMMOp(dst, rlo, rhi, zu)
		})
	case 0x21: // INSERTPS xmm, xmm/m32, imm8
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		imm, err := c.u8()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			slo, _, err := e.readXMMOp(src)
			if err != nil {
				return false, err
			}
			dlo, dhi, _ := e.readXMMOp(dst)
			// Extract src float (count_s from bits [7:6]).
			countS := int(imm >> 6 & 3)
			var srcF uint32
			if countS < 2 {
				srcF = uint32(slo >> uint(countS*32))
			} else {
				_, shi, _ := e.readXMMOp(src)
				srcF = uint32(shi >> uint((countS-2)*32))
			}
			rlo, rhi := sseInsertps(dlo, dhi, srcF, imm)
			return false, e.writeXMMOp(dst, rlo, rhi, zu)
		})
	case 0x22: // PINSRD xmm, r/m32, imm8  (or PINSRQ with REX.W)
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		imm, err := c.u8()
		if err != nil {
			return nil, err
		}
		w := 4
		if rexW {
			w = 8
		}
		return finish(func(e *Engine) (bool, error) {
			v, err := e.readOperand(src, w)
			if err != nil {
				return false, err
			}
			dlo, dhi, _ := e.readXMMOp(dst)
			var rlo, rhi uint64
			if w == 8 {
				rlo, rhi = ssePinsrq(dlo, dhi, v, imm)
			} else {
				rlo, rhi = ssePinsrd(dlo, dhi, uint32(v), imm)
			}
			return false, e.writeXMMOp(dst, rlo, rhi, zu)
		})
	case 0x40: // DPPS xmm, xmm/m128, imm8
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		imm, err := c.u8()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			slo, shi, err := e.readXMMOp(src)
			if err != nil {
				return false, err
			}
			dlo, dhi, _ := e.readXMMOp(dst)
			rlo, rhi := sseDpps(dlo, dhi, slo, shi, imm)
			return false, e.writeXMMOp(dst, rlo, rhi, zu)
		})
	case 0x41: // DPPD xmm, xmm/m128, imm8
		dst, src, err := decodeMR2()
		if err != nil {
			return nil, err
		}
		imm, err := c.u8()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			slo, shi, err := e.readXMMOp(src)
			if err != nil {
				return false, err
			}
			dlo, dhi, _ := e.readXMMOp(dst)
			rlo, rhi := sseDppd(dlo, dhi, slo, shi, imm)
			return false, e.writeXMMOp(dst, rlo, rhi, zu)
		})
	}
	return nil, fmt.Errorf("cpu: unsupported 0F 3A %#02x", op3)
}

// decodeVexInsn decodes and executes a VEX-prefixed instruction.
// op is the opcode byte that followed the VEX prefix bytes.
func (e *Engine) decodeVexInsn(
	c *cursor,
	op byte,
	rexPresent, rexW, rexR, rexX, rexB bool,
	vex vexState,
	applySeg func(operand) operand,
	width func(byteOp bool) int,
	finish func(func(*Engine) (bool, error)) (*decoded, error),
) (*decoded, error) {
	// The vvvv field is the 3rd register operand (for 3-operand forms).
	// It's already un-inverted in vexState.
	vvvv := vex.vvvv
	L := vex.L       // true = 256-bit (YMM)
	zu := true       // VEX writes always apply zero-upper rule for register targets

	decodeMR2 := func() (dst, src operand, err error) {
		mr, err := decodeModRM(e, c, rexR, rexX, rexB)
		if err != nil {
			return operand{}, operand{}, err
		}
		rm := applySeg(mr.rm)
		reg := operand{kind: opndReg, reg: mr.regField}
		return reg, rm, nil
	}
	decodeMR3 := func() (dst, src1Reg int, src2 operand, err error) {
		mr, err := decodeModRM(e, c, rexR, rexX, rexB)
		if err != nil {
			return 0, 0, operand{}, err
		}
		rm := applySeg(mr.rm)
		return mr.regField, vvvv, rm, nil
	}

	isPD := vex.opSize16()  // 66 → packed double / SSE2 int
	isSS := vex.repZ()     // F3 → scalar single
	isSD := vex.repNZ()    // F2 → scalar double

	switch vex.mapSelect {
	case 1: // 0F opcode map

		switch op {
		// ── Data movement ────────────────────────────────────────────────

		case 0x10: // VMOVUPS/SS/SD/UPD
			dst, src, err := decodeMR2()
			if err != nil {
				return nil, err
			}
			return finish(func(e *Engine) (bool, error) {
				if L {
					return false, e.execYMM(dst, src, func(_, _, _, _, slo, shi, shi0, shi1 uint64) (uint64, uint64, uint64, uint64) {
						return slo, shi, shi0, shi1
					})
				}
				return false, e.execXMM(dst, src, zu, func(_, _, slo, shi uint64) (uint64, uint64) { return slo, shi })
			})

		case 0x11: // VMOVUPS/SS/SD/UPD (store form)
			src, dst, err := decodeMR2()
			if err != nil {
				return nil, err
			}
			return finish(func(e *Engine) (bool, error) {
				if L {
					return false, e.execYMM(dst, src, func(_, _, _, _, slo, shi, shi0, shi1 uint64) (uint64, uint64, uint64, uint64) {
						return slo, shi, shi0, shi1
					})
				}
				return false, e.execXMM(dst, src, zu, func(_, _, slo, shi uint64) (uint64, uint64) { return slo, shi })
			})

		case 0x28: // VMOVAPS/APD xmm/ymm, xmm/m
			dst, src, err := decodeMR2()
			if err != nil {
				return nil, err
			}
			return finish(func(e *Engine) (bool, error) {
				if L {
					return false, e.execYMM(dst, src, func(_, _, _, _, slo, shi, shi0, shi1 uint64) (uint64, uint64, uint64, uint64) {
						return slo, shi, shi0, shi1
					})
				}
				return false, e.execXMM(dst, src, zu, func(_, _, slo, shi uint64) (uint64, uint64) { return slo, shi })
			})

		case 0x29: // VMOVAPS/APD (store)
			src, dst, err := decodeMR2()
			if err != nil {
				return nil, err
			}
			return finish(func(e *Engine) (bool, error) {
				if L {
					return false, e.execYMM(dst, src, func(_, _, _, _, slo, shi, shi0, shi1 uint64) (uint64, uint64, uint64, uint64) {
						return slo, shi, shi0, shi1
					})
				}
				return false, e.execXMM(dst, src, zu, func(_, _, slo, shi uint64) (uint64, uint64) { return slo, shi })
			})

		case 0x2A: // VCVTSI2SS / VCVTSI2SD
			dstReg, _, src2, err := decodeMR3()
			if err != nil {
				return nil, err
			}
			w := width(false)
			return finish(func(e *Engine) (bool, error) {
				iv, err := e.readOperand(src2, w)
				if err != nil {
					return false, err
				}
				intVal := int64(signExtend(iv, w*8))
				// VEX 3-operand: merge upper lanes from vvvv.
				mlo, mhi := e.regs.readXMM(vvvv)
				var rlo, rhi uint64
				if isSS {
					rlo, rhi = sseCvtsi2ss(mlo, mhi, intVal)
				} else {
					rlo, rhi = sseCvtsi2sd(mlo, mhi, intVal)
				}
				dst := operand{kind: opndReg, reg: dstReg}
				return false, e.writeXMMOp(dst, rlo, rhi, zu)
			})

		case 0x2C: // VCVTTSS2SI / VCVTTSD2SI
			dst, src, err := decodeMR2()
			if err != nil {
				return nil, err
			}
			w := width(false)
			return finish(func(e *Engine) (bool, error) {
				slo, _, err := e.readXMMOp(src)
				if err != nil {
					return false, err
				}
				var iv int64
				if isSS {
					iv = sseCvttss2si(slo)
				} else {
					iv = sseCvttsd2si(slo)
				}
				return false, e.writeOperand(dst, w, uint64(iv))
			})

		case 0x2D: // VCVTSS2SI / VCVTSD2SI
			dst, src, err := decodeMR2()
			if err != nil {
				return nil, err
			}
			w := width(false)
			return finish(func(e *Engine) (bool, error) {
				slo, _, err := e.readXMMOp(src)
				if err != nil {
					return false, err
				}
				var iv int64
				if isSS {
					iv = sseCvtss2si(slo)
				} else {
					iv = sseCvtsd2si(slo)
				}
				return false, e.writeOperand(dst, w, uint64(iv))
			})

		case 0x2E: // VUCOMISS / VUCOMISD
			dst, src, err := decodeMR2()
			if err != nil {
				return nil, err
			}
			return finish(func(e *Engine) (bool, error) {
				dlo, _, _ := e.readXMMOp(dst)
				slo, _, err := e.readXMMOp(src)
				if err != nil {
					return false, err
				}
				if isPD {
					e.sseComisd(dlo, slo)
				} else {
					e.sseComiss(dlo, slo)
				}
				return false, nil
			})

		case 0x2F: // VCOMISS / VCOMISD
			dst, src, err := decodeMR2()
			if err != nil {
				return nil, err
			}
			return finish(func(e *Engine) (bool, error) {
				dlo, _, _ := e.readXMMOp(dst)
				slo, _, err := e.readXMMOp(src)
				if err != nil {
					return false, err
				}
				if isPD {
					e.sseComisd(dlo, slo)
				} else {
					e.sseComiss(dlo, slo)
				}
				return false, nil
			})

		// ── 3-operand float arithmetic ───────────────────────────────────

		case 0x51: // VSQRTPS/PD/SS/SD
			dst, src, err := decodeMR2()
			if err != nil {
				return nil, err
			}
			return finish(func(e *Engine) (bool, error) {
				slo, shi, err := e.readXMMOp(src)
				if err != nil {
					return false, err
				}
				dlo, dhi, _ := e.readXMMOp(dst)
				var rlo, rhi uint64
				switch {
				case isSS:
					rlo, rhi = sseSqrtss(dlo, dhi, slo)
				case isSD:
					rlo, rhi = sseSqrtsd(slo, dhi, 0)
				case isPD:
					if L {
						slo2, shi2, err := e.readXMMOp(src)
						if err != nil {
							return false, err
						}
						rlo, rhi = e.sseSqrtpd(slo, shi)
						rlo2, rhi2 := e.sseSqrtpd(slo2, shi2)
						return false, e.writeYMMOp(dst, rlo, rhi, rlo2, rhi2)
					}
					rlo, rhi = e.sseSqrtpd(slo, shi)
				default:
					if L {
						slo2, shi2, _, _, err := e.readYMMOp(src)
						if err != nil {
							return false, err
						}
						rlo, rhi = e.sseSqrtps(slo, shi)
						rlo2, rhi2 := e.sseSqrtps(slo2, shi2)
						return false, e.writeYMMOp(dst, rlo, rhi, rlo2, rhi2)
					}
					rlo, rhi = e.sseSqrtps(slo, shi)
				}
				return false, e.writeXMMOp(dst, rlo, rhi, zu)
			})

		case 0x54: // VANDPS/PD
			dstReg, src1Reg, src2, err := decodeMR3()
			if err != nil {
				return nil, err
			}
			dst := operand{kind: opndReg, reg: dstReg}
			return finish(func(e *Engine) (bool, error) {
				if L {
					return false, e.execYMM3(dst, src1Reg, src2, func(s1lo, s1hi, s1hi0, s1hi1, s2lo, s2hi, s2hi0, s2hi1 uint64) (uint64, uint64, uint64, uint64) {
						return s1lo & s2lo, s1hi & s2hi, s1hi0 & s2hi0, s1hi1 & s2hi1
					})
				}
				return false, e.execXMM3(dst, src1Reg, src2, zu, func(s1lo, s1hi, s2lo, s2hi uint64) (uint64, uint64) {
					return s1lo & s2lo, s1hi & s2hi
				})
			})

		case 0x55: // VANDNPS/PD
			dstReg, src1Reg, src2, err := decodeMR3()
			if err != nil {
				return nil, err
			}
			dst := operand{kind: opndReg, reg: dstReg}
			return finish(func(e *Engine) (bool, error) {
				if L {
					return false, e.execYMM3(dst, src1Reg, src2, func(s1lo, s1hi, s1hi0, s1hi1, s2lo, s2hi, s2hi0, s2hi1 uint64) (uint64, uint64, uint64, uint64) {
						return ^s1lo & s2lo, ^s1hi & s2hi, ^s1hi0 & s2hi0, ^s1hi1 & s2hi1
					})
				}
				return false, e.execXMM3(dst, src1Reg, src2, zu, func(s1lo, s1hi, s2lo, s2hi uint64) (uint64, uint64) {
					return ^s1lo & s2lo, ^s1hi & s2hi
				})
			})

		case 0x56: // VORPS/PD
			dstReg, src1Reg, src2, err := decodeMR3()
			if err != nil {
				return nil, err
			}
			dst := operand{kind: opndReg, reg: dstReg}
			return finish(func(e *Engine) (bool, error) {
				if L {
					return false, e.execYMM3(dst, src1Reg, src2, func(s1lo, s1hi, s1hi0, s1hi1, s2lo, s2hi, s2hi0, s2hi1 uint64) (uint64, uint64, uint64, uint64) {
						return s1lo | s2lo, s1hi | s2hi, s1hi0 | s2hi0, s1hi1 | s2hi1
					})
				}
				return false, e.execXMM3(dst, src1Reg, src2, zu, func(s1lo, s1hi, s2lo, s2hi uint64) (uint64, uint64) {
					return s1lo | s2lo, s1hi | s2hi
				})
			})

		case 0x57: // VXORPS/PD
			dstReg, src1Reg, src2, err := decodeMR3()
			if err != nil {
				return nil, err
			}
			dst := operand{kind: opndReg, reg: dstReg}
			return finish(func(e *Engine) (bool, error) {
				if L {
					return false, e.execYMM3(dst, src1Reg, src2, func(s1lo, s1hi, s1hi0, s1hi1, s2lo, s2hi, s2hi0, s2hi1 uint64) (uint64, uint64, uint64, uint64) {
						return s1lo ^ s2lo, s1hi ^ s2hi, s1hi0 ^ s2hi0, s1hi1 ^ s2hi1
					})
				}
				return false, e.execXMM3(dst, src1Reg, src2, zu, func(s1lo, s1hi, s2lo, s2hi uint64) (uint64, uint64) {
					return s1lo ^ s2lo, s1hi ^ s2hi
				})
			})

		case 0x58: // VADDPS/PD/SS/SD
			dstReg, src1Reg, src2, err := decodeMR3()
			if err != nil {
				return nil, err
			}
			dst := operand{kind: opndReg, reg: dstReg}
			return finish(func(e *Engine) (bool, error) {
				s2lo, s2hi, err := e.readXMMOp(src2)
				if err != nil {
					return false, err
				}
				s1lo, s1hi := e.regs.readXMM(src1Reg)
				var rlo, rhi uint64
				switch {
				case isSS:
					rlo, rhi = sseAddss(s1lo, s1hi, s2lo, s2hi)
				case isSD:
					rlo, rhi = sseAddsd(s1lo, s1hi, s2lo, s2hi)
				case isPD:
					if L {
						s1lo2, s1hi2, s1hi3, s1hi4 := e.regs.readYMM(src1Reg)
						s2lo2, s2hi2, s2hi3, s2hi4, err := e.readYMMOp(src2)
						if err != nil {
							return false, err
						}
						_, _, _, _ = s1hi3, s1hi4, s2hi3, s2hi4
						rlo, rhi = e.sseAddpd(s1lo, s1hi, s2lo, s2hi)
						r2, r3 := e.sseAddpd(s1lo2, s1hi2, s2lo2, s2hi2)
						return false, e.writeYMMOp(dst, rlo, rhi, r2, r3)
					}
					rlo, rhi = e.sseAddpd(s1lo, s1hi, s2lo, s2hi)
				default:
					if L {
						s1lo2, s1hi2, _, _ := e.regs.readYMM(src1Reg)
						s2lo2, s2hi2, _, _, err := e.readYMMOp(src2)
						if err != nil {
							return false, err
						}
						rlo, rhi = e.sseAddps(s1lo, s1hi, s2lo, s2hi)
						r2, r3 := e.sseAddps(s1lo2, s1hi2, s2lo2, s2hi2)
						return false, e.writeYMMOp(dst, rlo, rhi, r2, r3)
					}
					rlo, rhi = e.sseAddps(s1lo, s1hi, s2lo, s2hi)
				}
				return false, e.writeXMMOp(dst, rlo, rhi, zu)
			})

		case 0x59: // VMULPS/PD/SS/SD
			dstReg, src1Reg, src2, err := decodeMR3()
			if err != nil {
				return nil, err
			}
			dst := operand{kind: opndReg, reg: dstReg}
			return finish(func(e *Engine) (bool, error) {
				return false, e.vexBinop(dst, src1Reg, src2, isSS, isSD, isPD, L, zu,
					sseMulss, sseMulsd, e.sseMulpd, e.sseMulps)
			})

		case 0x5A: // VCVTPS2PD / VCVTPD2PS / VCVTSS2SD / VCVTSD2SS
			dstReg, _, src2, err := decodeMR3()
			if err != nil {
				return nil, err
			}
			dst := operand{kind: opndReg, reg: dstReg}
			return finish(func(e *Engine) (bool, error) {
				slo, shi, err := e.readXMMOp(src2)
				if err != nil {
					return false, err
				}
				mlo, mhi := e.regs.readXMM(vvvv)
				var rlo, rhi uint64
				switch {
				case isSS:
					rlo, rhi = sseCvtss2sd(mlo, mhi, slo, shi)
				case isSD:
					rlo, rhi = sseCvtsd2ss(mlo, mhi, slo, shi)
				case isPD:
					rlo, rhi = sseCvtpd2ps(slo, shi)
				default:
					rlo, rhi = sseCvtps2pd(slo, shi)
				}
				return false, e.writeXMMOp(dst, rlo, rhi, zu)
			})

		case 0x5C: // VSUBPS/PD/SS/SD
			dstReg, src1Reg, src2, err := decodeMR3()
			if err != nil {
				return nil, err
			}
			dst := operand{kind: opndReg, reg: dstReg}
			return finish(func(e *Engine) (bool, error) {
				return false, e.vexBinop(dst, src1Reg, src2, isSS, isSD, isPD, L, zu,
					sseSubss, sseSubsd, e.sseSubpd, e.sseSubps)
			})

		case 0x5D: // VMINPS/PD/SS/SD
			dstReg, src1Reg, src2, err := decodeMR3()
			if err != nil {
				return nil, err
			}
			dst := operand{kind: opndReg, reg: dstReg}
			return finish(func(e *Engine) (bool, error) {
				return false, e.vexBinop(dst, src1Reg, src2, isSS, isSD, isPD, L, zu,
					sseMinss, sseMinsd, e.sseMinpd, e.sseMinps)
			})

		case 0x5E: // VDIVPS/PD/SS/SD
			dstReg, src1Reg, src2, err := decodeMR3()
			if err != nil {
				return nil, err
			}
			dst := operand{kind: opndReg, reg: dstReg}
			return finish(func(e *Engine) (bool, error) {
				return false, e.vexBinop(dst, src1Reg, src2, isSS, isSD, isPD, L, zu,
					sseDivss, sseDivsd, e.sseDivpd, e.sseDivps)
			})

		case 0x5F: // VMAXPS/PD/SS/SD
			dstReg, src1Reg, src2, err := decodeMR3()
			if err != nil {
				return nil, err
			}
			dst := operand{kind: opndReg, reg: dstReg}
			return finish(func(e *Engine) (bool, error) {
				return false, e.vexBinop(dst, src1Reg, src2, isSS, isSD, isPD, L, zu,
					sseMaxss, sseMaxsd, e.sseMaxpd, e.sseMaxps)
			})

		// ── SSE2 integer (VEX-encoded) ────────────────────────────────────

		case 0x6E: // VMOVD xmm, r/m32  (VMOVQ with REX.W)
			dst, src, err := decodeMR2()
			if err != nil {
				return nil, err
			}
			w := 4
			if rexW {
				w = 8
			}
			return finish(func(e *Engine) (bool, error) {
				v, err := e.readOperand(src, w)
				if err != nil {
					return false, err
				}
				return false, e.writeXMMOp(dst, v, 0, zu)
			})

		case 0x6F: // VMOVDQA / VMOVDQU
			dst, src, err := decodeMR2()
			if err != nil {
				return nil, err
			}
			return finish(func(e *Engine) (bool, error) {
				if L {
					return false, e.execYMM(dst, src, func(_, _, _, _, s0, s1, s2, s3 uint64) (uint64, uint64, uint64, uint64) {
						return s0, s1, s2, s3
					})
				}
				return false, e.execXMM(dst, src, zu, func(_, _, slo, shi uint64) (uint64, uint64) { return slo, shi })
			})

		case 0x70: // VPSHUFD/PSHUFHW/PSHUFLW
			dst, src, err := decodeMR2()
			if err != nil {
				return nil, err
			}
			imm, err := c.u8()
			if err != nil {
				return nil, err
			}
			return finish(func(e *Engine) (bool, error) {
				slo, shi, err := e.readXMMOp(src)
				if err != nil {
					return false, err
				}
				var rlo, rhi uint64
				switch {
				case isSS:
					rlo, rhi = ssePshufhw(slo, shi, imm)
				case isSD:
					rlo, rhi = ssePshuflw(slo, shi, imm)
				default:
					rlo, rhi = ssePshufd(slo, shi, imm)
				}
				return false, e.writeXMMOp(dst, rlo, rhi, zu)
			})

		case 0x7E: // VMOVD r/m32, xmm  (VMOVQ with REX.W)  /  F3: VMOVQ xmm, xmm/m64
			if isSS {
				dst, src, err := decodeMR2()
				if err != nil {
					return nil, err
				}
				return finish(func(e *Engine) (bool, error) {
					slo, _, err := e.readXMMOp(src)
					if err != nil {
						return false, err
					}
					return false, e.writeXMMOp(dst, slo, 0, zu)
				})
			}
			src, dst, err := decodeMR2()
			if err != nil {
				return nil, err
			}
			w := 4
			if rexW {
				w = 8
			}
			return finish(func(e *Engine) (bool, error) {
				slo, _, _ := e.readXMMOp(src)
				return false, e.writeOperand(dst, w, slo)
			})

		case 0x7F: // VMOVDQA/VMOVDQU (store)
			src, dst, err := decodeMR2()
			if err != nil {
				return nil, err
			}
			return finish(func(e *Engine) (bool, error) {
				if L {
					return false, e.execYMM(dst, src, func(_, _, _, _, s0, s1, s2, s3 uint64) (uint64, uint64, uint64, uint64) {
						return s0, s1, s2, s3
					})
				}
				return false, e.execXMM(dst, src, zu, func(_, _, slo, shi uint64) (uint64, uint64) { return slo, shi })
			})

		// Integer 3-operand VEX ops.
		case 0xD4: // VPADDQ
			dstReg, src1Reg, src2, err := decodeMR3()
			if err != nil {
				return nil, err
			}
			dst := operand{kind: opndReg, reg: dstReg}
			return finish(func(e *Engine) (bool, error) {
				return false, e.execXMM3(dst, src1Reg, src2, zu, e.ssePaddq)
			})
		case 0xDB: // VPAND
			dstReg, src1Reg, src2, err := decodeMR3()
			if err != nil {
				return nil, err
			}
			dst := operand{kind: opndReg, reg: dstReg}
			return finish(func(e *Engine) (bool, error) {
				return false, e.execXMM3(dst, src1Reg, src2, zu, e.ssePand)
			})
		case 0xDF: // VPANDN
			dstReg, src1Reg, src2, err := decodeMR3()
			if err != nil {
				return nil, err
			}
			dst := operand{kind: opndReg, reg: dstReg}
			return finish(func(e *Engine) (bool, error) {
				return false, e.execXMM3(dst, src1Reg, src2, zu, e.ssePandn)
			})
		case 0xEB: // VPOR
			dstReg, src1Reg, src2, err := decodeMR3()
			if err != nil {
				return nil, err
			}
			dst := operand{kind: opndReg, reg: dstReg}
			return finish(func(e *Engine) (bool, error) {
				return false, e.execXMM3(dst, src1Reg, src2, zu, e.ssePor)
			})
		case 0xEF: // VPXOR
			dstReg, src1Reg, src2, err := decodeMR3()
			if err != nil {
				return nil, err
			}
			dst := operand{kind: opndReg, reg: dstReg}
			return finish(func(e *Engine) (bool, error) {
				return false, e.execXMM3(dst, src1Reg, src2, zu, e.ssePxor)
			})
		case 0xF8: // VPSUBB
			dstReg, src1Reg, src2, err := decodeMR3()
			if err != nil {
				return nil, err
			}
			dst := operand{kind: opndReg, reg: dstReg}
			return finish(func(e *Engine) (bool, error) {
				return false, e.execXMM3(dst, src1Reg, src2, zu, e.ssePsubb)
			})
		case 0xF9: // VPSUBW
			dstReg, src1Reg, src2, err := decodeMR3()
			if err != nil {
				return nil, err
			}
			dst := operand{kind: opndReg, reg: dstReg}
			return finish(func(e *Engine) (bool, error) {
				return false, e.execXMM3(dst, src1Reg, src2, zu, e.ssePsubw)
			})
		case 0xFA: // VPSUBD
			dstReg, src1Reg, src2, err := decodeMR3()
			if err != nil {
				return nil, err
			}
			dst := operand{kind: opndReg, reg: dstReg}
			return finish(func(e *Engine) (bool, error) {
				return false, e.execXMM3(dst, src1Reg, src2, zu, e.ssePsubd)
			})
		case 0xFB: // VPSUBQ
			dstReg, src1Reg, src2, err := decodeMR3()
			if err != nil {
				return nil, err
			}
			dst := operand{kind: opndReg, reg: dstReg}
			return finish(func(e *Engine) (bool, error) {
				return false, e.execXMM3(dst, src1Reg, src2, zu, e.ssePsubq)
			})
		case 0xFC: // VPADDB
			dstReg, src1Reg, src2, err := decodeMR3()
			if err != nil {
				return nil, err
			}
			dst := operand{kind: opndReg, reg: dstReg}
			return finish(func(e *Engine) (bool, error) {
				return false, e.execXMM3(dst, src1Reg, src2, zu, e.ssePaddb)
			})
		case 0xFD: // VPADDW
			dstReg, src1Reg, src2, err := decodeMR3()
			if err != nil {
				return nil, err
			}
			dst := operand{kind: opndReg, reg: dstReg}
			return finish(func(e *Engine) (bool, error) {
				return false, e.execXMM3(dst, src1Reg, src2, zu, e.ssePaddw)
			})
		case 0xFE: // VPADDD
			dstReg, src1Reg, src2, err := decodeMR3()
			if err != nil {
				return nil, err
			}
			dst := operand{kind: opndReg, reg: dstReg}
			return finish(func(e *Engine) (bool, error) {
				return false, e.execXMM3(dst, src1Reg, src2, zu, e.ssePaddd)
			})
		}

	case 2: // 0F 38 opcode map (VEX)
		switch op {
		case 0x00: // VPSHUFB
			dstReg, src1Reg, src2, err := decodeMR3()
			if err != nil {
				return nil, err
			}
			dst := operand{kind: opndReg, reg: dstReg}
			return finish(func(e *Engine) (bool, error) {
				s2lo, s2hi, err := e.readXMMOp(src2)
				if err != nil {
					return false, err
				}
				s1lo, s1hi := e.regs.readXMM(src1Reg)
				rlo, rhi := ssePshufb(s1lo, s1hi, s2lo, s2hi)
				return false, e.writeXMMOp(dst, rlo, rhi, zu)
			})

		case 0x17: // VPTEST
			dst, src, err := decodeMR2()
			if err != nil {
				return nil, err
			}
			return finish(func(e *Engine) (bool, error) {
				slo, shi, err := e.readXMMOp(src)
				if err != nil {
					return false, err
				}
				dlo, dhi, _ := e.readXMMOp(dst)
				e.ssePtest(dlo, dhi, slo, shi)
				return false, nil
			})

		// VBROADCAST family (AVX only, map 2)
		case 0x18: // VBROADCASTSS xmm/ymm, m32
			dst, src, err := decodeMR2()
			if err != nil {
				return nil, err
			}
			return finish(func(e *Engine) (bool, error) {
				slo, _, err := e.readXMMOp(src)
				if err != nil {
					return false, err
				}
				f := uint32(slo)
				rlo0, rlo1, rhi0, rhi1 := sseVbroadcastss(f, L)
				if L {
					return false, e.writeYMMOp(dst, rlo0, rlo1, rhi0, rhi1)
				}
				return false, e.writeXMMOp(dst, rlo0, rlo1, zu)
			})

		case 0x19: // VBROADCASTSD ymm, m64
			dst, src, err := decodeMR2()
			if err != nil {
				return nil, err
			}
			return finish(func(e *Engine) (bool, error) {
				slo, _, err := e.readXMMOp(src)
				if err != nil {
					return false, err
				}
				r0, r1, r2, r3 := sseVbroadcastsd(slo)
				if L {
					return false, e.writeYMMOp(dst, r0, r1, r2, r3)
				}
				return false, e.writeXMMOp(dst, r0, r1, zu)
			})

		case 0x28: // VPMULDQ
			dstReg, src1Reg, src2, err := decodeMR3()
			if err != nil {
				return nil, err
			}
			dst := operand{kind: opndReg, reg: dstReg}
			return finish(func(e *Engine) (bool, error) {
				return false, e.execXMM3(dst, src1Reg, src2, zu, e.ssePmuldq)
			})

		case 0x29: // VPCMPEQQ
			dstReg, src1Reg, src2, err := decodeMR3()
			if err != nil {
				return nil, err
			}
			dst := operand{kind: opndReg, reg: dstReg}
			return finish(func(e *Engine) (bool, error) {
				return false, e.execXMM3(dst, src1Reg, src2, zu, e.ssePcmpeqq)
			})

		case 0x37: // VPCMPGTQ
			dstReg, src1Reg, src2, err := decodeMR3()
			if err != nil {
				return nil, err
			}
			dst := operand{kind: opndReg, reg: dstReg}
			return finish(func(e *Engine) (bool, error) {
				return false, e.execXMM3(dst, src1Reg, src2, zu, e.ssePcmpgtq)
			})

		case 0x40: // VPMULLD
			dstReg, src1Reg, src2, err := decodeMR3()
			if err != nil {
				return nil, err
			}
			dst := operand{kind: opndReg, reg: dstReg}
			return finish(func(e *Engine) (bool, error) {
				return false, e.execXMM3(dst, src1Reg, src2, zu, e.ssePmulld)
			})
		}

	case 3: // 0F 3A opcode map (VEX)
		switch op {
		case 0x04: // VPERMILPS (VEX-only)
			// imm8 variant: VPERMILPS xmm/ymm, xmm/m, imm8
			dst, src, err := decodeMR2()
			if err != nil {
				return nil, err
			}
			imm, err := c.u8()
			if err != nil {
				return nil, err
			}
			return finish(func(e *Engine) (bool, error) {
				slo, shi, err := e.readXMMOp(src)
				if err != nil {
					return false, err
				}
				rlo, rhi := ssePshufd(slo, shi, imm)
				return false, e.writeXMMOp(dst, rlo, rhi, zu)
			})

		case 0x06: // VPERM2F128 ymm, ymm, ymm/m256, imm8
			dstReg, src1Reg, src2, err := decodeMR3()
			if err != nil {
				return nil, err
			}
			imm, err := c.u8()
			if err != nil {
				return nil, err
			}
			dst := operand{kind: opndReg, reg: dstReg}
			return finish(func(e *Engine) (bool, error) {
				d0, d1, d2, d3 := e.regs.readYMM(src1Reg)
				s0, s1, s2, s3, err := e.readYMMOp(src2)
				if err != nil {
					return false, err
				}
				r0, r1, r2, r3 := sseVperm2f128(d0, d1, d2, d3, s0, s1, s2, s3, imm)
				return false, e.writeYMMOp(dst, r0, r1, r2, r3)
			})

		case 0x0F: // VPALIGNR
			dstReg, src1Reg, src2, err := decodeMR3()
			if err != nil {
				return nil, err
			}
			imm, err := c.u8()
			if err != nil {
				return nil, err
			}
			dst := operand{kind: opndReg, reg: dstReg}
			return finish(func(e *Engine) (bool, error) {
				s2lo, s2hi, err := e.readXMMOp(src2)
				if err != nil {
					return false, err
				}
				s1lo, s1hi := e.regs.readXMM(src1Reg)
				rlo, rhi := ssePalignr(s1lo, s1hi, s2lo, s2hi, imm)
				return false, e.writeXMMOp(dst, rlo, rhi, zu)
			})

		case 0x18: // VINSERTF128 ymm, ymm, xmm/m128, imm8
			dstReg, src1Reg, src2, err := decodeMR3()
			if err != nil {
				return nil, err
			}
			imm, err := c.u8()
			if err != nil {
				return nil, err
			}
			dst := operand{kind: opndReg, reg: dstReg}
			return finish(func(e *Engine) (bool, error) {
				d0, d1, d2, d3 := e.regs.readYMM(src1Reg)
				s0, s1, err := e.readXMMOp(src2)
				if err != nil {
					return false, err
				}
				r0, r1, r2, r3 := sseVinsertf128(d0, d1, d2, d3, s0, s1, imm)
				return false, e.writeYMMOp(dst, r0, r1, r2, r3)
			})

		case 0x19: // VEXTRACTF128 xmm/m128, ymm, imm8
			src, dst, err := decodeMR2()
			if err != nil {
				return nil, err
			}
			imm, err := c.u8()
			if err != nil {
				return nil, err
			}
			return finish(func(e *Engine) (bool, error) {
				d0, d1, d2, d3, err := e.readYMMOp(src)
				if err != nil {
					return false, err
				}
				rlo, rhi := sseVextractf128(d0, d1, d2, d3, imm)
				return false, e.writeXMMOp(dst, rlo, rhi, zu)
			})

		case 0x20: // VPINSRB
			dstReg, src1Reg, src2, err := decodeMR3()
			if err != nil {
				return nil, err
			}
			imm, err := c.u8()
			if err != nil {
				return nil, err
			}
			dst := operand{kind: opndReg, reg: dstReg}
			return finish(func(e *Engine) (bool, error) {
				v, err := e.readOperand(src2, 4)
				if err != nil {
					return false, err
				}
				s1lo, s1hi := e.regs.readXMM(src1Reg)
				rlo, rhi := ssePinsrb(s1lo, s1hi, uint8(v), imm)
				return false, e.writeXMMOp(dst, rlo, rhi, zu)
			})

		case 0x21: // VINSERTPS
			dstReg, src1Reg, src2, err := decodeMR3()
			if err != nil {
				return nil, err
			}
			imm, err := c.u8()
			if err != nil {
				return nil, err
			}
			dst := operand{kind: opndReg, reg: dstReg}
			return finish(func(e *Engine) (bool, error) {
				slo, _, err := e.readXMMOp(src2)
				if err != nil {
					return false, err
				}
				d1lo, d1hi := e.regs.readXMM(src1Reg)
				countS := int(imm >> 6 & 3)
				var srcF uint32
				if countS < 2 {
					srcF = uint32(slo >> uint(countS*32))
				} else {
					_, shi, _ := e.readXMMOp(src2)
					srcF = uint32(shi >> uint((countS-2)*32))
				}
				rlo, rhi := sseInsertps(d1lo, d1hi, srcF, imm)
				return false, e.writeXMMOp(dst, rlo, rhi, zu)
			})

		case 0x22: // VPINSRD / VPINSRQ
			dstReg, src1Reg, src2, err := decodeMR3()
			if err != nil {
				return nil, err
			}
			imm, err := c.u8()
			if err != nil {
				return nil, err
			}
			w := 4
			if rexW {
				w = 8
			}
			dst := operand{kind: opndReg, reg: dstReg}
			return finish(func(e *Engine) (bool, error) {
				v, err := e.readOperand(src2, w)
				if err != nil {
					return false, err
				}
				s1lo, s1hi := e.regs.readXMM(src1Reg)
				var rlo, rhi uint64
				if w == 8 {
					rlo, rhi = ssePinsrq(s1lo, s1hi, v, imm)
				} else {
					rlo, rhi = ssePinsrd(s1lo, s1hi, uint32(v), imm)
				}
				return false, e.writeXMMOp(dst, rlo, rhi, zu)
			})

		case 0x38: // VINSERTI128
			dstReg, src1Reg, src2, err := decodeMR3()
			if err != nil {
				return nil, err
			}
			imm, err := c.u8()
			if err != nil {
				return nil, err
			}
			dst := operand{kind: opndReg, reg: dstReg}
			return finish(func(e *Engine) (bool, error) {
				d0, d1, d2, d3 := e.regs.readYMM(src1Reg)
				s0, s1, err := e.readXMMOp(src2)
				if err != nil {
					return false, err
				}
				r0, r1, r2, r3 := sseVinsertf128(d0, d1, d2, d3, s0, s1, imm)
				return false, e.writeYMMOp(dst, r0, r1, r2, r3)
			})

		case 0x39: // VEXTRACTI128
			src, dst, err := decodeMR2()
			if err != nil {
				return nil, err
			}
			imm, err := c.u8()
			if err != nil {
				return nil, err
			}
			return finish(func(e *Engine) (bool, error) {
				d0, d1, d2, d3, err := e.readYMMOp(src)
				if err != nil {
					return false, err
				}
				rlo, rhi := sseVextractf128(d0, d1, d2, d3, imm)
				return false, e.writeXMMOp(dst, rlo, rhi, zu)
			})
		}
	}

	return nil, fmt.Errorf("cpu: VEX map%d %#02x (66=%v F3=%v F2=%v) not implemented",
		vex.mapSelect, op, isPD, isSS, isSD)
}

// vexBinop is a helper that dispatches 4-way SS/SD/PD/PS VEX binary
// operations for both 128-bit (XMM) and 256-bit (YMM) variants.
func (e *Engine) vexBinop(
	dst operand, src1Reg int, src2 operand,
	isSS, isSD, isPD, L, zu bool,
	fnSS func(dlo, dhi, slo, shi uint64) (uint64, uint64),
	fnSD func(dlo, dhi, slo, shi uint64) (uint64, uint64),
	fnPD func(dlo, dhi, slo, shi uint64) (uint64, uint64),
	fnPS func(dlo, dhi, slo, shi uint64) (uint64, uint64),
) error {
	switch {
	case isSS:
		return e.execXMM3(dst, src1Reg, src2, zu, fnSS)
	case isSD:
		return e.execXMM3(dst, src1Reg, src2, zu, fnSD)
	case isPD:
		if L {
			return e.execYMM3(dst, src1Reg, src2, func(s1lo, s1hi, s1hi0, s1hi1, s2lo, s2hi, s2hi0, s2hi1 uint64) (uint64, uint64, uint64, uint64) {
				r0, r1 := fnPD(s1lo, s1hi, s2lo, s2hi)
				r2, r3 := fnPD(s1hi0, s1hi1, s2hi0, s2hi1)
				return r0, r1, r2, r3
			})
		}
		return e.execXMM3(dst, src1Reg, src2, zu, fnPD)
	default: // PS
		if L {
			return e.execYMM3(dst, src1Reg, src2, func(s1lo, s1hi, s1hi0, s1hi1, s2lo, s2hi, s2hi0, s2hi1 uint64) (uint64, uint64, uint64, uint64) {
				r0, r1 := fnPS(s1lo, s1hi, s2lo, s2hi)
				r2, r3 := fnPS(s1hi0, s1hi1, s2hi0, s2hi1)
				return r0, r1, r2, r3
			})
		}
		return e.execXMM3(dst, src1Reg, src2, zu, fnPS)
	}
}
