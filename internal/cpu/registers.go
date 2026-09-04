package cpu

// Registers holds the 16 general-purpose registers plus RIP, RFLAGS,
// the two segment bases the emulator actually uses (FS_BASE for TLS --
// see arch_prctl -- and GS_BASE, tracked for symmetry), and the
// SSE/AVX vector register file.
type Registers struct {
	gpr    [16]uint64
	rip    uint64
	rflags uint64
	fsbase uint64
	gsbase uint64

	// SSE/AVX vector registers.
	//
	// xmm[i] holds the low 128 bits of YMM[i] as a [lo64, hi64] pair;
	// it is exactly XMM[i].  ymmHi[i] holds the upper 128 bits of
	// YMM[i].  Real hardware splits them the same way (XSAVE area).
	//
	// Write rules that match real x86:
	//  - SSE (non-VEX) instructions write xmm[i] and leave ymmHi[i]
	//    unchanged.
	//  - VEX-encoded instructions with L=0 (128-bit) write xmm[i] and
	//    ZERO ymmHi[i] ("zero-upper" rule).
	//  - VEX-encoded instructions with L=1 (256-bit) write the full
	//    YMM[i] = xmm[i] + ymmHi[i].
	xmm   [16][2]uint64 // [i][0]=lo64, [i][1]=hi64 of XMM[i]
	ymmHi [16][2]uint64 // upper 128 bits of YMM[i]

	// mxcsr is the SSE control/status register (rounding mode, exception
	// masks, flush-to-zero, etc.).  LDMXCSR/STMXCSR read/write it, but
	// the emulator does not currently change the host FPU rounding mode
	// in response -- it always operates at round-to-nearest, which is
	// what every normally-compiled program expects.
	mxcsr uint32
}

// EFLAGS bit positions used by flags.go.
const (
	flagCF = 1 << 0
	flagPF = 1 << 2
	flagAF = 1 << 4
	flagZF = 1 << 6
	flagSF = 1 << 7
	flagDF = 1 << 10
	flagOF = 1 << 11
)

// read8/write8 implement the legacy AH/CH/DH/BH high-byte encoding:
// register indices 4-7 (SP/BP/SI/DI in the 16/32/64-bit tables) mean
// "high byte of AX/CX/DX/BX" for an 8-bit operand *only when no REX
// prefix is present*. With REX present, 4-7 instead mean the low byte
// of SPL/BPL/SIL/DIL, and 8-15 (only reachable with REX) mean the low
// byte of R8B-R15B.
func (r *Registers) read8(idx int, rex bool) uint8 {
	if !rex && idx >= 4 && idx <= 7 {
		return uint8(r.gpr[idx-4] >> 8)
	}
	return uint8(r.gpr[idx])
}

func (r *Registers) write8(idx int, rex bool, v uint8) {
	if !rex && idx >= 4 && idx <= 7 {
		reg := idx - 4
		r.gpr[reg] = (r.gpr[reg] &^ 0xFF00) | uint64(v)<<8
		return
	}
	r.gpr[idx] = (r.gpr[idx] &^ 0xFF) | uint64(v)
}

func (r *Registers) read16(idx int) uint16 { return uint16(r.gpr[idx]) }
func (r *Registers) write16(idx int, v uint16) {
	r.gpr[idx] = (r.gpr[idx] &^ 0xFFFF) | uint64(v)
}

func (r *Registers) read32(idx int) uint32 { return uint32(r.gpr[idx]) }

// write32 zero-extends into the full 64-bit register, matching real
// x86-64 semantics ("mov eax, ..." clears the top 32 bits of rax).
func (r *Registers) write32(idx int, v uint32) { r.gpr[idx] = uint64(v) }

func (r *Registers) read64(idx int) uint64     { return r.gpr[idx] }
func (r *Registers) write64(idx int, v uint64) { r.gpr[idx] = v }

// readWidth/writeWidth dispatch on operand width in bytes (1/2/4/8).
func (r *Registers) readWidth(idx, width int, rex bool) uint64 {
	switch width {
	case 1:
		return uint64(r.read8(idx, rex))
	case 2:
		return uint64(r.read16(idx))
	case 4:
		return uint64(r.read32(idx))
	default:
		return r.read64(idx)
	}
}

func (r *Registers) writeWidth(idx, width int, rex bool, val uint64) {
	switch width {
	case 1:
		r.write8(idx, rex, uint8(val))
	case 2:
		r.write16(idx, uint16(val))
	case 4:
		r.write32(idx, uint32(val))
	default:
		r.write64(idx, val)
	}
}

// -- XMM / YMM accessors ------------------------------------------------

// readXMM returns the 128-bit XMM[i] as (lo, hi) pair.
func (r *Registers) readXMM(i int) (lo, hi uint64) {
	return r.xmm[i][0], r.xmm[i][1]
}

// writeXMM stores (lo, hi) into XMM[i] without touching the upper YMM
// bits -- this is the SSE (non-VEX) write rule.
func (r *Registers) writeXMM(i int, lo, hi uint64) {
	r.xmm[i][0] = lo
	r.xmm[i][1] = hi
}

// writeXMMVex stores (lo, hi) into XMM[i] and zeros the upper 128 bits
// of YMM[i] -- the VEX L=0 "zero-upper" write rule.
func (r *Registers) writeXMMVex(i int, lo, hi uint64) {
	r.xmm[i][0] = lo
	r.xmm[i][1] = hi
	r.ymmHi[i][0] = 0
	r.ymmHi[i][1] = 0
}

// readYMM returns all four 64-bit lanes of YMM[i]: lo0 and lo1 are the
// low 128 bits (= XMM[i]), hi0 and hi1 are the upper 128 bits.
func (r *Registers) readYMM(i int) (lo0, lo1, hi0, hi1 uint64) {
	return r.xmm[i][0], r.xmm[i][1], r.ymmHi[i][0], r.ymmHi[i][1]
}

// writeYMM stores all four 64-bit lanes into YMM[i] -- the VEX L=1
// (256-bit) write rule.
func (r *Registers) writeYMM(i int, lo0, lo1, hi0, hi1 uint64) {
	r.xmm[i][0] = lo0
	r.xmm[i][1] = lo1
	r.ymmHi[i][0] = hi0
	r.ymmHi[i][1] = hi1
}
