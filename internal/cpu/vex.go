package cpu

// vexState captures every field decoded from a VEX (or EVEX) prefix.
// The zero value represents "no VEX prefix present".
//
// VEX encoding overview
// ─────────────────────
//
// 2-byte VEX (lead byte 0xC5):
//
//	byte 1: [R̄  ṽṽṽṽ  L  pp]
//
// 3-byte VEX (lead byte 0xC4):
//
//	byte 1: [R̄  X̄  B̄  map_select]
//	byte 2: [W  ṽṽṽṽ  L  pp]
//
// Bars indicate stored-complement (0 in the field means the extension
// bit is 1).  R/X/B in this struct hold the *actual* extension bit
// after inverting.
//
// pp encodes an implied legacy prefix:
//
//	0 = none (no SSE prefix → NP / packed-single context)
//	1 = 0x66  (packed-double / SSE2-integer context)
//	2 = 0xF3  (scalar-single context)
//	3 = 0xF2  (scalar-double context)
//
// mapSelect encodes the opcode escape:
//
//	1 = 0F    (most SSE/AVX opcodes)
//	2 = 0F 38 (SSSE3 / SSE4.1 opcodes)
//	3 = 0F 3A (SSE4.1 immediate opcodes)
type vexState struct {
	present   bool
	R, X, B   bool  // register-index extension bits (true = extend by 8)
	W         bool  // REX.W equivalent for integer ops with GPR operands
	vvvv      int   // 3rd/4th operand register, 0-15, already un-inverted
	L         bool  // true = 256-bit YMM operation
	pp        uint8 // 0-3, implied legacy prefix
	mapSelect int   // 1, 2, or 3
}

// decodeVEXPrefix reads a VEX prefix from c.  It is called after the
// legacy-prefix scan in decodeOne has confirmed that the next byte is
// 0xC4 (3-byte VEX) or 0xC5 (2-byte VEX) -- the lead byte itself has
// already been consumed by the caller.
func decodeVEXPrefix(c *cursor, lead byte) (vexState, error) {
	var v vexState
	v.present = true

	switch lead {
	case 0xC5: // 2-byte VEX
		b, err := c.u8()
		if err != nil {
			return vexState{}, err
		}
		// R̄ is bit 7; R = !R̄
		v.R = b&0x80 == 0
		// vvvv is bits 6-3, stored inverted; un-invert
		v.vvvv = int(^b>>3) & 0xF
		v.L = b&0x04 != 0
		v.pp = b & 0x03
		// 2-byte VEX implies: X=false, B=false, W=false, map_select=1 (0F)
		v.mapSelect = 1

	case 0xC4: // 3-byte VEX
		b1, err := c.u8()
		if err != nil {
			return vexState{}, err
		}
		b2, err := c.u8()
		if err != nil {
			return vexState{}, err
		}
		v.R = b1&0x80 == 0
		v.X = b1&0x40 == 0
		v.B = b1&0x20 == 0
		v.mapSelect = int(b1 & 0x1F)

		v.W = b2&0x80 != 0
		v.vvvv = int(^b2>>3) & 0xF
		v.L = b2&0x04 != 0
		v.pp = b2 & 0x03
	}
	return v, nil
}

// vexOpSize16 reports whether the VEX prefix implies a 0x66 operand-
// size override (pp==1), used to distinguish packed-double / SSE2-
// integer operations from packed-single operations.
func (v vexState) opSize16() bool { return v.pp == 1 }

// vexRepZ reports whether the VEX pp field implies 0xF3 (scalar-single).
func (v vexState) repZ() bool { return v.pp == 2 }

// vexRepNZ reports whether the VEX pp field implies 0xF2 (scalar-double).
func (v vexState) repNZ() bool { return v.pp == 3 }
