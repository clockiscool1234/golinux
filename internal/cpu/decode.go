package cpu

import "fmt"

// decoded is one fully-decoded instruction: its length in bytes (for
// advancing RIP on fall-through) and a closure that performs its
// semantics. exec returns branched=true if it already updated RIP
// itself (jumps/calls/rets); otherwise the caller advances RIP by len.
//
// insnID is InsSyscall/InsCpuid for those two instructions (which are
// handled specially by the run loop via HookInsn -- see cpu.go) and
// -1 for everything else.
type decoded struct {
	len    int
	insnID int
	exec   func(e *Engine) (branched bool, err error)
}

// repKind identifies which (if any) REP-family legacy prefix preceded
// an instruction. The same 0xF3 byte means plain "REP" for MOVS/
// STOS/LODS and "REPE/REPZ" for CMPS/SCAS; 0xF2 ("REPNE/REPNZ") is
// only meaningful for CMPS/SCAS.
type repKind int

const (
	repNone repKind = iota
	repZ
	repNZ
)

const noInsnHook = -1

func (e *Engine) evalCC(cc int) bool {
	cf, zf, sf, of, pf := e.flag(flagCF), e.flag(flagZF), e.flag(flagSF), e.flag(flagOF), e.flag(flagPF)
	switch cc & 0xF {
	case 0x0:
		return of
	case 0x1:
		return !of
	case 0x2:
		return cf
	case 0x3:
		return !cf
	case 0x4:
		return zf
	case 0x5:
		return !zf
	case 0x6:
		return cf || zf
	case 0x7:
		return !cf && !zf
	case 0x8:
		return sf
	case 0x9:
		return !sf
	case 0xA:
		return pf
	case 0xB:
		return !pf
	case 0xC:
		return sf != of
	case 0xD:
		return sf == of
	case 0xE:
		return zf || sf != of
	case 0xF:
		return !zf && sf == of
	}
	return false
}

// aluBinOp applies one of the eight ADD/OR/ADC/SBB/AND/SUB/XOR/CMP
// operations (the standard x86 "grp1" operation index, also used by
// the 0x00-0x3D opcode block) to dst/src, writing the result back to
// dst unless it's CMP (index 7), and setting flags throughout.
func (e *Engine) aluBinOp(idx int, dst, src operand, width int) error {
	a, err := e.readOperand(dst, width)
	if err != nil {
		return err
	}
	b, err := e.readOperand(src, width)
	if err != nil {
		return err
	}
	var result uint64
	switch idx {
	case 0: // ADD
		result = e.addWithFlags(a, b, width)
	case 1: // OR
		result = a | b
		e.logicFlags(result, width)
	case 2: // ADC
		cin := uint64(0)
		if e.flag(flagCF) {
			cin = 1
		}
		result = e.addWithFlagsCarry(a, b, width, cin)
	case 3: // SBB
		bin := uint64(0)
		if e.flag(flagCF) {
			bin = 1
		}
		result = e.subWithFlagsBorrow(a, b, width, bin)
	case 4: // AND
		result = a & b
		e.logicFlags(result, width)
	case 5: // SUB
		result = e.subWithFlags(a, b, width)
	case 6: // XOR
		result = a ^ b
		e.logicFlags(result, width)
	case 7: // CMP
		e.subWithFlags(a, b, width)
		return nil
	default:
		return fmt.Errorf("cpu: bad alu op index %d", idx)
	}
	return e.writeOperand(dst, width, result)
}

// decodeOne decodes the single instruction at addr.
func (e *Engine) decodeOne(addr uint64) (*decoded, error) {
	c := &cursor{e: e, base: addr}

	opSize16 := false
	segFS, segGS := false, false
	rep := repNone
	var rex byte
	rexPresent := false

legacyPrefixes:
	for {
		b, err := c.peekByte()
		if err != nil {
			return nil, err
		}
		switch b {
		case 0x66:
			opSize16 = true
			c.pos++
		case 0x67, 0xF0, 0x2E, 0x36, 0x3E, 0x26:
			c.pos++
		case 0xF2:
			rep = repNZ
			c.pos++
		case 0xF3:
			rep = repZ
			c.pos++
		case 0x64:
			segFS = true
			c.pos++
		case 0x65:
			segGS = true
			c.pos++
		default:
			break legacyPrefixes
		}
	}
	// Declare rex extension bits here so they are in scope for both the
	// VEX path below and the normal REX / opcode path further down.
	var rexW, rexR, rexX, rexB bool

	if b, err := c.peekByte(); err == nil && (b == 0xC4 || b == 0xC5) {
		// VEX prefix: consumes the lead byte, then decodes the rest.
		c.pos++
		vx, err := decodeVEXPrefix(c, b)
		if err != nil {
			return nil, err
		}
		// VEX overrides all legacy prefixes that were parsed above.
		opSize16 = vx.opSize16()
		if vx.repZ() {
			rep = repZ
		} else if vx.repNZ() {
			rep = repNZ
		} else {
			rep = repNone
		}
		rexPresent = true
		rexW = vx.W
		rexR = vx.R
		rexX = vx.X
		rexB = vx.B
		// Re-derive rex for completeness.
		rex = 0x40
		if rexW {
			rex |= 0x08
		}
		if rexR {
			rex |= 0x04
		}
		if rexX {
			rex |= 0x02
		}
		if rexB {
			rex |= 0x01
		}

		// width / applySeg closures need to be defined before calling
		// decodeVexInsn so that the call site can pass them in.
		// They are identical to the ones set up for the normal path below.
		vexWidth := func(byteOp bool) int {
			if byteOp {
				return 1
			}
			if rexW {
				return 8
			}
			if opSize16 {
				return 2
			}
			return 4
		}
		vexApplySeg := func(o operand) operand {
			if o.kind != opndMem || o.ripRelative {
				return o
			}
			if segFS {
				o.addr += e.regs.fsbase
			} else if segGS {
				o.addr += e.regs.gsbase
			}
			return o
		}
		vexFinish := func(fn func(*Engine) (bool, error)) (*decoded, error) {
			return &decoded{len: c.pos, exec: fn}, nil
		}

		// Read the actual opcode byte (no 0x0F escape for VEX).
		vop, err := c.u8()
		if err != nil {
			return nil, err
		}
		return e.decodeVexInsn(c, vop, rexPresent, rexW, rexR, rexX, rexB, vx, vexApplySeg, vexWidth, vexFinish)
	} else if b, err := c.peekByte(); err == nil && b >= 0x40 && b <= 0x4F {
		rex = b
		rexPresent = true
		c.pos++
	}
	// Populate rex extension bits from the rex byte (normal non-VEX path).
	// These were declared above and may already be set by the VEX path
	// (which returns early), so this block is only reached for non-VEX.
	rexW = rex&0x08 != 0
	rexR = rex&0x04 != 0
	rexX = rex&0x02 != 0
	rexB = rex&0x01 != 0

	width := func(byteOp bool) int {
		if byteOp {
			return 1
		}
		if rexW {
			return 8
		}
		if opSize16 {
			return 2
		}
		return 4
	}

	// applySeg adds the FS/GS base to a resolved memory operand's
	// address when the corresponding legacy prefix was present. Only
	// FS/GS are modeled (see package doc comment) since that's what
	// TLS access compiles down to.
	applySeg := func(o operand) operand {
		if o.kind != opndMem || o.ripRelative {
			return o
		}
		if segFS {
			o.addr += e.regs.fsbase
		} else if segGS {
			o.addr += e.regs.gsbase
		}
		return o
	}

	op, err := c.u8()
	if err != nil {
		return nil, err
	}

	d := &decoded{insnID: noInsnHook}
	finish := func(exec func(e *Engine) (bool, error)) (*decoded, error) {
		d.len = c.pos
		d.exec = exec
		return d, nil
	}

	switch {
	// -- one-byte ALU ops: ADD/OR/ADC/SBB/AND/SUB/XOR/CMP ------------
	case op <= 0x3D && op&0xC0 == 0x00 && (op&0x07) <= 5:
		idx := int(op >> 3)
		form := op & 7
		switch form {
		case 0, 1, 2, 3: // Eb,Gb / Ev,Gv / Gb,Eb / Gv,Ev
			byteOp := form == 0 || form == 2
			w := width(byteOp)
			mr, err := decodeModRM(e, c, rexR, rexX, rexB)
			if err != nil {
				return nil, err
			}
			rm := applySeg(mr.rm)
			reg := regOperand(mr.regField, rexPresent)
			dst, src := rm, reg
			if form == 2 || form == 3 {
				dst, src = reg, rm
			}
			return finish(func(e *Engine) (bool, error) { return false, e.aluBinOp(idx, dst, src, w) })
		case 4: // AL, ib
			w := 1
			imm, err := c.u8()
			if err != nil {
				return nil, err
			}
			dst, src := regOperand(0, rexPresent), immOperand(uint64(imm))
			return finish(func(e *Engine) (bool, error) { return false, e.aluBinOp(idx, dst, src, w) })
		case 5: // eAX, iz
			w := width(false)
			var immV uint64
			if w == 2 {
				v, err := c.u16()
				if err != nil {
					return nil, err
				}
				immV = signExtend(uint64(v), 16)
			} else {
				v, err := c.i32()
				if err != nil {
					return nil, err
				}
				immV = uint64(int64(v))
			}
			dst, src := regOperand(0, rexPresent), immOperand(immV)
			return finish(func(e *Engine) (bool, error) { return false, e.aluBinOp(idx, dst, src, w) })
		}

	case op == 0x80, op == 0x81, op == 0x83: // group1: r/m, imm
		byteOp := op == 0x80
		w := width(byteOp)
		mr, err := decodeModRM(e, c, rexR, rexX, rexB)
		if err != nil {
			return nil, err
		}
		rm := applySeg(mr.rm)
		idx := mr.regField & 7
		var immV uint64
		switch {
		case op == 0x80:
			v, err := c.u8()
			if err != nil {
				return nil, err
			}
			immV = signExtend(uint64(v), 8)
		case op == 0x81:
			if w == 2 {
				v, err := c.u16()
				if err != nil {
					return nil, err
				}
				immV = signExtend(uint64(v), 16)
			} else {
				v, err := c.i32()
				if err != nil {
					return nil, err
				}
				immV = uint64(int64(v))
			}
		case op == 0x83:
			v, err := c.i8()
			if err != nil {
				return nil, err
			}
			immV = uint64(int64(v))
		}
		src := immOperand(immV)
		return finish(func(e *Engine) (bool, error) { return false, e.aluBinOp(idx, rm, src, w) })

	// -- TEST -----------------------------------------------------------
	case op == 0x84, op == 0x85: // TEST r/m, r
		byteOp := op == 0x84
		w := width(byteOp)
		mr, err := decodeModRM(e, c, rexR, rexX, rexB)
		if err != nil {
			return nil, err
		}
		rm := applySeg(mr.rm)
		reg := regOperand(mr.regField, rexPresent)
		return finish(func(e *Engine) (bool, error) {
			a, err := e.readOperand(rm, w)
			if err != nil {
				return false, err
			}
			b, err := e.readOperand(reg, w)
			if err != nil {
				return false, err
			}
			e.logicFlags(a&b, w)
			return false, nil
		})
	case op == 0xA8, op == 0xA9: // TEST AL/eAX, imm
		byteOp := op == 0xA8
		w := width(byteOp)
		var immV uint64
		if byteOp {
			v, err := c.u8()
			if err != nil {
				return nil, err
			}
			immV = uint64(v)
		} else if w == 2 {
			v, err := c.u16()
			if err != nil {
				return nil, err
			}
			immV = uint64(v)
		} else {
			v, err := c.i32()
			if err != nil {
				return nil, err
			}
			immV = uint64(int64(v)) & maskWidth(w)
		}
		return finish(func(e *Engine) (bool, error) {
			a, err := e.readOperand(regOperand(0, rexPresent), w)
			if err != nil {
				return false, err
			}
			e.logicFlags(a&immV, w)
			return false, nil
		})

	// -- MOV --------------------------------------------------------
	case op == 0x88, op == 0x89, op == 0x8A, op == 0x8B:
		byteOp := op == 0x88 || op == 0x8A
		w := width(byteOp)
		mr, err := decodeModRM(e, c, rexR, rexX, rexB)
		if err != nil {
			return nil, err
		}
		rm := applySeg(mr.rm)
		reg := regOperand(mr.regField, rexPresent)
		dst, src := rm, reg
		if op == 0x8A || op == 0x8B {
			dst, src = reg, rm
		}
		return finish(func(e *Engine) (bool, error) {
			v, err := e.readOperand(src, w)
			if err != nil {
				return false, err
			}
			return false, e.writeOperand(dst, w, v)
		})
	case op == 0xC6, op == 0xC7: // MOV r/m, imm
		byteOp := op == 0xC6
		w := width(byteOp)
		mr, err := decodeModRM(e, c, rexR, rexX, rexB)
		if err != nil {
			return nil, err
		}
		rm := applySeg(mr.rm)
		var immV uint64
		if byteOp {
			v, err := c.u8()
			if err != nil {
				return nil, err
			}
			immV = uint64(v)
		} else if w == 2 {
			v, err := c.u16()
			if err != nil {
				return nil, err
			}
			immV = uint64(v)
		} else {
			v, err := c.i32()
			if err != nil {
				return nil, err
			}
			immV = uint64(int64(v)) & maskWidth(w)
		}
		return finish(func(e *Engine) (bool, error) { return false, e.writeOperand(rm, w, immV) })
	case op >= 0xB0 && op <= 0xB7: // MOV r8, imm8
		reg := int(op-0xB0) | boolBit(rexB)<<3
		imm, err := c.u8()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			return false, e.writeOperand(regOperand(reg, rexPresent), 1, uint64(imm))
		})
	case op >= 0xB8 && op <= 0xBF: // MOV r, imm (16/32/64)
		reg := int(op-0xB8) | boolBit(rexB)<<3
		w := width(false)
		var immV uint64
		if w == 8 {
			v, err := c.u64()
			if err != nil {
				return nil, err
			}
			immV = v
		} else if w == 2 {
			v, err := c.u16()
			if err != nil {
				return nil, err
			}
			immV = uint64(v)
		} else {
			v, err := c.u32()
			if err != nil {
				return nil, err
			}
			immV = uint64(v)
		}
		return finish(func(e *Engine) (bool, error) { return false, e.writeOperand(regOperand(reg, rexPresent), w, immV) })

	// -- LEA ----------------------------------------------------------
	case op == 0x8D:
		mr, err := decodeModRM(e, c, rexR, rexX, rexB)
		if err != nil {
			return nil, err
		}
		w := width(false)
		reg := regOperand(mr.regField, rexPresent)
		return finish(func(e *Engine) (bool, error) {
			a, err := e.leaAddr(mr.rm)
			if err != nil {
				return false, err
			}
			return false, e.writeOperand(reg, w, a)
		})

	// -- PUSH/POP -----------------------------------------------------
	case op >= 0x50 && op <= 0x57:
		reg := int(op-0x50) | boolBit(rexB)<<3
		return finish(func(e *Engine) (bool, error) {
			v := e.regs.read64(reg)
			return false, e.push64(v)
		})
	case op >= 0x58 && op <= 0x5F:
		reg := int(op-0x58) | boolBit(rexB)<<3
		return finish(func(e *Engine) (bool, error) {
			v, err := e.pop64()
			if err != nil {
				return false, err
			}
			e.regs.write64(reg, v)
			return false, nil
		})
	case op == 0x68: // PUSH imm32
		v, err := c.i32()
		if err != nil {
			return nil, err
		}
		imm := uint64(int64(v))
		return finish(func(e *Engine) (bool, error) { return false, e.push64(imm) })
	case op == 0x6A: // PUSH imm8
		v, err := c.i8()
		if err != nil {
			return nil, err
		}
		imm := uint64(int64(v))
		return finish(func(e *Engine) (bool, error) { return false, e.push64(imm) })

	// -- XCHG -----------------------------------------------------------
	case op == 0x86, op == 0x87:
		byteOp := op == 0x86
		w := width(byteOp)
		mr, err := decodeModRM(e, c, rexR, rexX, rexB)
		if err != nil {
			return nil, err
		}
		rm := applySeg(mr.rm)
		reg := regOperand(mr.regField, rexPresent)
		return finish(func(e *Engine) (bool, error) {
			a, err := e.readOperand(rm, w)
			if err != nil {
				return false, err
			}
			b, err := e.readOperand(reg, w)
			if err != nil {
				return false, err
			}
			if err := e.writeOperand(rm, w, b); err != nil {
				return false, err
			}
			return false, e.writeOperand(reg, w, a)
		})

	// -- MOVZX/MOVSX/MOVSXD -----------------------------------------
	case op == 0x0F:
		return e.decodeTwoByte(c, rexPresent, rexW, rexR, rexX, rexB, opSize16, rep, applySeg, width, finish)
	case op == 0x63: // MOVSXD r64, r/m32
		mr, err := decodeModRM(e, c, rexR, rexX, rexB)
		if err != nil {
			return nil, err
		}
		rm := applySeg(mr.rm)
		reg := regOperand(mr.regField, rexPresent)
		return finish(func(e *Engine) (bool, error) {
			v, err := e.readOperand(rm, 4)
			if err != nil {
				return false, err
			}
			return false, e.writeOperand(reg, 8, signExtend(v, 32))
		})

	// -- IMUL r,r/m,imm -----------------------------------------------
	case op == 0x69, op == 0x6B:
		w := width(false)
		mr, err := decodeModRM(e, c, rexR, rexX, rexB)
		if err != nil {
			return nil, err
		}
		rm := applySeg(mr.rm)
		reg := regOperand(mr.regField, rexPresent)
		var immV uint64
		if op == 0x6B {
			v, err := c.i8()
			if err != nil {
				return nil, err
			}
			immV = uint64(int64(v))
		} else if w == 2 {
			v, err := c.u16()
			if err != nil {
				return nil, err
			}
			immV = signExtend(uint64(v), 16)
		} else {
			v, err := c.i32()
			if err != nil {
				return nil, err
			}
			immV = uint64(int64(v))
		}
		return finish(func(e *Engine) (bool, error) {
			a, err := e.readOperand(rm, w)
			if err != nil {
				return false, err
			}
			return false, e.imul2(reg, a, immV, w)
		})

	// -- INC/DEC/NOT/NEG/MUL/IMUL/DIV/IDIV (0xF6/0xF7, 0xFE/0xFF) ------
	case op == 0xF6, op == 0xF7:
		byteOp := op == 0xF6
		w := width(byteOp)
		mr, err := decodeModRM(e, c, rexR, rexX, rexB)
		if err != nil {
			return nil, err
		}
		rm := applySeg(mr.rm)
		idx := mr.regField & 7
		if idx == 0 || idx == 1 { // TEST r/m, imm
			var immV uint64
			if byteOp {
				v, err := c.u8()
				if err != nil {
					return nil, err
				}
				immV = uint64(v)
			} else if w == 2 {
				v, err := c.u16()
				if err != nil {
					return nil, err
				}
				immV = uint64(v)
			} else {
				v, err := c.i32()
				if err != nil {
					return nil, err
				}
				immV = uint64(int64(v)) & maskWidth(w)
			}
			return finish(func(e *Engine) (bool, error) {
				a, err := e.readOperand(rm, w)
				if err != nil {
					return false, err
				}
				e.logicFlags(a&immV, w)
				return false, nil
			})
		}
		return finish(func(e *Engine) (bool, error) { return false, e.grp3Op(idx, rm, w) })
	case op == 0xFE, op == 0xFF:
		byteOp := op == 0xFE
		w := width(byteOp)
		mr, err := decodeModRM(e, c, rexR, rexX, rexB)
		if err != nil {
			return nil, err
		}
		rm := applySeg(mr.rm)
		idx := mr.regField & 7
		switch idx {
		case 0: // INC
			return finish(func(e *Engine) (bool, error) {
				a, err := e.readOperand(rm, w)
				if err != nil {
					return false, err
				}
				return false, e.writeOperand(rm, w, e.incFlags(a, w))
			})
		case 1: // DEC
			return finish(func(e *Engine) (bool, error) {
				a, err := e.readOperand(rm, w)
				if err != nil {
					return false, err
				}
				return false, e.writeOperand(rm, w, e.decFlags(a, w))
			})
		case 2: // CALL r/m64 (near, indirect)
			return finish(func(e *Engine) (bool, error) {
				target, err := e.readOperand(rm, 8)
				if err != nil {
					return false, err
				}
				if err := e.push64(e.curInstrEnd); err != nil {
					return false, err
				}
				e.regs.rip = target
				return true, nil
			})
		case 4: // JMP r/m64 (near, indirect)
			return finish(func(e *Engine) (bool, error) {
				target, err := e.readOperand(rm, 8)
				if err != nil {
					return false, err
				}
				e.regs.rip = target
				return true, nil
			})
		case 6: // PUSH r/m64
			return finish(func(e *Engine) (bool, error) {
				v, err := e.readOperand(rm, 8)
				if err != nil {
					return false, err
				}
				return false, e.push64(v)
			})
		default:
			return nil, fmt.Errorf("cpu: unsupported /%d for opcode %#x", idx, op)
		}

	// -- Shift group (C0/C1/D0-D3) -------------------------------------
	case op == 0xC0, op == 0xC1, op == 0xD0, op == 0xD1, op == 0xD2, op == 0xD3:
		byteOp := op == 0xC0 || op == 0xD0 || op == 0xD2
		w := width(byteOp)
		mr, err := decodeModRM(e, c, rexR, rexX, rexB)
		if err != nil {
			return nil, err
		}
		rm := applySeg(mr.rm)
		idx := mr.regField & 7
		var countImm *uint8
		if op == 0xC0 || op == 0xC1 {
			v, err := c.u8()
			if err != nil {
				return nil, err
			}
			countImm = &v
		}
		return finish(func(e *Engine) (bool, error) {
			var count int
			switch {
			case countImm != nil:
				count = int(*countImm)
			case op == 0xD0 || op == 0xD1:
				count = 1
			default: // D2/D3: count in CL
				count = int(e.regs.read8(1, rexPresent))
			}
			return false, e.shiftGrp2(idx, rm, w, count)
		})

	// -- INT3/HLT are decode errors for now; not needed by the target
	// workload and better to fault loudly than silently misbehave.

	// -- control flow -----------------------------------------------
	case op == 0xE8: // CALL rel32
		rel, err := c.i32()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			target := e.curInstrEnd + uint64(int64(rel))
			if err := e.push64(e.curInstrEnd); err != nil {
				return false, err
			}
			e.regs.rip = target
			return true, nil
		})
	case op == 0xE9: // JMP rel32
		rel, err := c.i32()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			e.regs.rip = e.curInstrEnd + uint64(int64(rel))
			return true, nil
		})
	case op == 0xEB: // JMP rel8
		rel, err := c.i8()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			e.regs.rip = e.curInstrEnd + uint64(int64(rel))
			return true, nil
		})
	case op >= 0x70 && op <= 0x7F: // Jcc rel8
		cc := int(op - 0x70)
		rel, err := c.i8()
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
	case op == 0xC3: // RET
		return finish(func(e *Engine) (bool, error) {
			target, err := e.pop64()
			if err != nil {
				return false, err
			}
			e.regs.rip = target
			return true, nil
		})
	case op == 0xC2: // RET imm16
		n, err := c.u16()
		if err != nil {
			return nil, err
		}
		return finish(func(e *Engine) (bool, error) {
			target, err := e.pop64()
			if err != nil {
				return false, err
			}
			e.regs.gpr[RegRSP] += uint64(n)
			e.regs.rip = target
			return true, nil
		})
	case op == 0xC9: // LEAVE
		return finish(func(e *Engine) (bool, error) {
			e.regs.gpr[RegRSP] = e.regs.gpr[RegRBP]
			v, err := e.pop64()
			if err != nil {
				return false, err
			}
			e.regs.gpr[RegRBP] = v
			return false, nil
		})

	// -- CDQE/CWDE/CBW, CQO/CDQ/CWD -----------------------------------
	case op == 0x98:
		w := width(false)
		return finish(func(e *Engine) (bool, error) {
			switch w {
			case 8:
				e.regs.write64(0, signExtend(uint64(e.regs.read32(0)), 32))
			case 4: // CWDE: sign-extend AX(16) into EAX(32)
				e.regs.write32(0, uint32(signExtend(uint64(e.regs.read16(0)), 16)))
			case 2: // CBW: sign-extend AL(8) into AX(16)
				v := int8(e.regs.read8(0, rexPresent))
				e.regs.write16(0, uint16(int16(v)))
			}
			return false, nil
		})
	case op == 0x99:
		w := width(false)
		return finish(func(e *Engine) (bool, error) {
			switch w {
			case 8:
				v := int64(e.regs.read64(0))
				if v < 0 {
					e.regs.write64(2, ^uint64(0))
				} else {
					e.regs.write64(2, 0)
				}
			case 4:
				v := int32(e.regs.read32(0))
				if v < 0 {
					e.regs.write32(2, 0xFFFFFFFF)
				} else {
					e.regs.write32(2, 0)
				}
			case 2:
				v := int16(e.regs.read16(0))
				if v < 0 {
					e.regs.write16(2, 0xFFFF)
				} else {
					e.regs.write16(2, 0)
				}
			}
			return false, nil
		})

	// -- NOP ------------------------------------------------------------
	case op == 0x90:
		return finish(func(e *Engine) (bool, error) { return false, nil })

	// -- XCHG rAX, r (short form 0x91-0x97) ----------------------------
	case op >= 0x91 && op <= 0x97:
		reg := int(op-0x90) | boolBit(rexB)<<3
		w := width(false)
		return finish(func(e *Engine) (bool, error) {
			a, err := e.readOperand(regOperand(RegRAX, rexPresent), w)
			if err != nil {
				return false, err
			}
			b, err := e.readOperand(regOperand(reg, rexPresent), w)
			if err != nil {
				return false, err
			}
			if err := e.writeOperand(regOperand(RegRAX, rexPresent), w, b); err != nil {
				return false, err
			}
			return false, e.writeOperand(regOperand(reg, rexPresent), w, a)
		})

	// -- CLD/STD (direction flag) --------------------------------------
	case op == 0xFC:
		return finish(func(e *Engine) (bool, error) { e.setFlag(flagDF, false); return false, nil })
	case op == 0xFD:
		return finish(func(e *Engine) (bool, error) { e.setFlag(flagDF, true); return false, nil })

	// -- string instructions (MOVS/STOS/LODS/CMPS/SCAS) -----------------
	case op == 0xA4, op == 0xA5: // MOVS
		byteOp := op == 0xA4
		w := width(byteOp)
		return finish(func(e *Engine) (bool, error) { return false, e.strMovs(w, rep) })
	case op == 0xAA, op == 0xAB: // STOS
		byteOp := op == 0xAA
		w := width(byteOp)
		return finish(func(e *Engine) (bool, error) { return false, e.strStos(w, rep, rexPresent) })
	case op == 0xAC, op == 0xAD: // LODS
		byteOp := op == 0xAC
		w := width(byteOp)
		return finish(func(e *Engine) (bool, error) { return false, e.strLods(w, rep, rexPresent) })
	case op == 0xA6, op == 0xA7: // CMPS
		byteOp := op == 0xA6
		w := width(byteOp)
		return finish(func(e *Engine) (bool, error) { return false, e.strCmps(w, rep) })
	case op == 0xAE, op == 0xAF: // SCAS
		byteOp := op == 0xAE
		w := width(byteOp)
		return finish(func(e *Engine) (bool, error) { return false, e.strScas(w, rep, rexPresent) })
	}

	return nil, fmt.Errorf("cpu: unsupported opcode %#02x at %#x", op, addr)
}
