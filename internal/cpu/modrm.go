package cpu

// cursor reads instruction bytes from guest memory starting at base,
// tracking how many bytes have been consumed so far (pos). Every read
// goes through the permission-checked fetch path (ProtExec), so an
// attempt to decode an instruction that straddles into unmapped or
// non-executable memory faults exactly like a real fetch would.
type cursor struct {
	e    *Engine
	base uint64
	pos  int
}

func (c *cursor) fetch(n int) ([]byte, error) {
	b, err := c.e.mem.readChecked(c.base+uint64(c.pos), n, ProtExec)
	if err != nil {
		return nil, err
	}
	c.pos += n
	return b, nil
}

func (c *cursor) peekByte() (byte, error) {
	b, err := c.e.mem.readChecked(c.base+uint64(c.pos), 1, ProtExec)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (c *cursor) u8() (uint8, error) {
	b, err := c.fetch(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (c *cursor) i8() (int8, error) {
	b, err := c.u8()
	return int8(b), err
}

func (c *cursor) u16() (uint16, error) {
	b, err := c.fetch(2)
	if err != nil {
		return 0, err
	}
	return uint16(leToU64(b)), nil
}

func (c *cursor) u32() (uint32, error) {
	b, err := c.fetch(4)
	if err != nil {
		return 0, err
	}
	return uint32(leToU64(b)), nil
}

func (c *cursor) i32() (int32, error) {
	v, err := c.u32()
	return int32(v), err
}

func (c *cursor) u64() (uint64, error) {
	b, err := c.fetch(8)
	if err != nil {
		return 0, err
	}
	return leToU64(b), nil
}

func boolBit(b bool) int {
	if b {
		return 1
	}
	return 0
}

// modrmResult is what decoding a ModRM (+ SIB + displacement) byte
// sequence produces: the "reg" field (always a register index, used
// either as a second operand or an opcode-extension digit) and the
// "r/m" field, which is either a plain register or a resolved memory
// operand.
type modrmResult struct {
	regField int
	rm       operand
}

// decodeModRM reads the ModRM byte (and SIB/displacement bytes, if
// the addressing mode calls for them) from c, using rexR/rexX/rexB to
// extend the reg/index/base fields into the full 0-15 range.
// rexPresent -- whether *any* REX prefix byte preceded this
// instruction, regardless of which bits it set -- matters separately
// from rexR/rexX/rexB: a register-direct (mod==3) r/m operand with a
// raw encoding of 4-7 means the AH/CH/DH/BH high-byte registers when
// no REX prefix is present at all, but SPL/BPL/SIL/DIL (or, extended
// by rexB, R12B-R15B) when one is -- see Registers.read8/write8. That
// distinction only matters for 8-bit operand widths, but decodeModRM
// itself doesn't know the eventual operand width (callers apply it
// via readOperand/writeOperand's width parameter), so it must record
// rexPresent on the operand unconditionally and let read8/write8
// decide whether it's relevant.
func decodeModRM(e *Engine, c *cursor, rexPresent, rexR, rexX, rexB bool) (modrmResult, error) {
	b, err := c.u8()
	if err != nil {
		return modrmResult{}, err
	}
	mod := b >> 6
	regRaw := (b >> 3) & 7
	rmRaw := b & 7

	regField := int(regRaw) | boolBit(rexR)<<3

	if mod == 3 {
		return modrmResult{regField: regField, rm: regOperand(int(rmRaw)|boolBit(rexB)<<3, rexPresent)}, nil
	}

	var base, index uint64
	var haveBase, haveIndex bool
	var baseReg, indexReg int

	if rmRaw == 4 {
		// SIB byte follows.
		sib, err := c.u8()
		if err != nil {
			return modrmResult{}, err
		}
		scale := uint64(1) << (sib >> 6)
		indexRaw := (sib >> 3) & 7
		baseRaw := sib & 7
		indexField := int(indexRaw) | boolBit(rexX)<<3
		if indexField != 4 { // index==4 (unextended) means "no index"
			indexReg = indexField
			haveIndex = true
			index = e.regs.read64(indexReg) * scale
		}
		if baseRaw == 5 && mod == 0 {
			// No base register; disp32 follows instead.
			d, err := c.i32()
			if err != nil {
				return modrmResult{}, err
			}
			base = uint64(int64(d))
			haveBase = true // "base" here is really just the disp32 constant
		} else {
			baseReg = int(baseRaw) | boolBit(rexB)<<3
			base = e.regs.read64(baseReg)
			haveBase = true
		}
	} else if mod == 0 && rmRaw == 5 {
		// RIP-relative: disp32 follows, address resolved once the
		// instruction's total length is known (see operand.go).
		d, err := c.i32()
		if err != nil {
			return modrmResult{}, err
		}
		return modrmResult{regField: regField, rm: memOperandRIP(int64(d))}, nil
	} else {
		baseReg = int(rmRaw) | boolBit(rexB)<<3
		base = e.regs.read64(baseReg)
		haveBase = true
	}
	_ = haveIndex

	var disp int64
	switch mod {
	case 1:
		d, err := c.i8()
		if err != nil {
			return modrmResult{}, err
		}
		disp = int64(d)
	case 2:
		d, err := c.i32()
		if err != nil {
			return modrmResult{}, err
		}
		disp = int64(d)
	}

	addr := base + index
	if disp < 0 {
		addr -= uint64(-disp)
	} else {
		addr += uint64(disp)
	}
	if !haveBase && !haveIndex {
		addr = uint64(disp)
	}
	return modrmResult{regField: regField, rm: memOperand(addr)}, nil
}
