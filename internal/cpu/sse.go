package cpu

import (
	"fmt"
	"math"
)

// ── XMM / YMM operand helpers ─────────────────────────────────────────────

// readXMMOp reads a 128-bit XMM value from either an XMM register or a
// 16-byte memory operand, returning it as (lo, hi) uint64.
func (e *Engine) readXMMOp(o operand) (lo, hi uint64, err error) {
	if o.kind == opndMem {
		addr := e.effAddr(o)
		buf, err := e.mem.readChecked(addr, 16, ProtRead)
		if err != nil {
			return 0, 0, err
		}
		return leToU64(buf[:8]), leToU64(buf[8:]), nil
	}
	l, h := e.regs.readXMM(o.reg)
	return l, h, nil
}

// writeXMMOp writes (lo, hi) to an XMM register or memory operand.
// zeroUpper true applies the VEX zero-upper rule for register targets.
func (e *Engine) writeXMMOp(o operand, lo, hi uint64, zeroUpper bool) error {
	if o.kind == opndMem {
		addr := e.effAddr(o)
		buf := make([]byte, 16)
		copy(buf[:8], u64ToLE(lo, 8))
		copy(buf[8:], u64ToLE(hi, 8))
		return e.mem.writeChecked(addr, buf, ProtWrite)
	}
	if zeroUpper {
		e.regs.writeXMMVex(o.reg, lo, hi)
	} else {
		e.regs.writeXMM(o.reg, lo, hi)
	}
	return nil
}

// readYMMOp reads a 256-bit YMM value (lo0, lo1, hi0, hi1) from a YMM
// register or a 32-byte memory operand.
func (e *Engine) readYMMOp(o operand) (lo0, lo1, hi0, hi1 uint64, err error) {
	if o.kind == opndMem {
		addr := e.effAddr(o)
		buf, err := e.mem.readChecked(addr, 32, ProtRead)
		if err != nil {
			return 0, 0, 0, 0, err
		}
		return leToU64(buf[:8]), leToU64(buf[8:16]),
			leToU64(buf[16:24]), leToU64(buf[24:32]), nil
	}
	a, b, c, d := e.regs.readYMM(o.reg)
	return a, b, c, d, nil
}

// writeYMMOp writes a full 256-bit YMM value to a register or memory.
func (e *Engine) writeYMMOp(o operand, lo0, lo1, hi0, hi1 uint64) error {
	if o.kind == opndMem {
		addr := e.effAddr(o)
		buf := make([]byte, 32)
		copy(buf[:8], u64ToLE(lo0, 8))
		copy(buf[8:16], u64ToLE(lo1, 8))
		copy(buf[16:24], u64ToLE(hi0, 8))
		copy(buf[24:32], u64ToLE(hi1, 8))
		return e.mem.writeChecked(addr, buf, ProtWrite)
	}
	e.regs.writeYMM(o.reg, lo0, lo1, hi0, hi1)
	return nil
}

// ── Lane arithmetic helpers ───────────────────────────────────────────────
//
// All helpers below operate on one or two 128-bit values represented as
// (lo, hi) uint64 pairs and apply a per-lane operation, returning the
// result as a new (lo, hi) pair.
//
// The lane width (1/2/4/8 bytes) selects which laneXX function to use.

// lane8 applies f to every 8-bit lane in (alo, ahi) and (blo, bhi).
func lane8(alo, ahi, blo, bhi uint64, f func(a, b uint8) uint8) (lo, hi uint64) {
	for i := 0; i < 8; i++ {
		shift := uint(i * 8)
		ra := f(uint8(alo>>shift), uint8(blo>>shift))
		rb := f(uint8(ahi>>shift), uint8(bhi>>shift))
		lo |= uint64(ra) << shift
		hi |= uint64(rb) << shift
	}
	return
}

// lane16 applies f to every 16-bit lane.
func lane16(alo, ahi, blo, bhi uint64, f func(a, b uint16) uint16) (lo, hi uint64) {
	for i := 0; i < 4; i++ {
		shift := uint(i * 16)
		ra := f(uint16(alo>>shift), uint16(blo>>shift))
		rb := f(uint16(ahi>>shift), uint16(bhi>>shift))
		lo |= uint64(ra) << shift
		hi |= uint64(rb) << shift
	}
	return
}

// lane32 applies f to every 32-bit lane.
func lane32(alo, ahi, blo, bhi uint64, f func(a, b uint32) uint32) (lo, hi uint64) {
	for i := 0; i < 2; i++ {
		shift := uint(i * 32)
		ra := f(uint32(alo>>shift), uint32(blo>>shift))
		rb := f(uint32(ahi>>shift), uint32(bhi>>shift))
		lo |= uint64(ra) << shift
		hi |= uint64(rb) << shift
	}
	return
}

// lane64 applies f to the two 64-bit lanes.
func lane64(alo, ahi, blo, bhi uint64, f func(a, b uint64) uint64) (lo, hi uint64) {
	return f(alo, blo), f(ahi, bhi)
}

// map8 applies f to every 8-bit lane of one operand.
func map8(alo, ahi uint64, f func(a uint8) uint8) (lo, hi uint64) {
	return lane8(alo, ahi, 0, 0, func(a, _ uint8) uint8 { return f(a) })
}

// map32f applies f to the four 32-bit float lanes.
func map32f(alo, ahi uint64, f func(float32) float32) (lo, hi uint64) {
	for i := 0; i < 2; i++ {
		shift := uint(i * 32)
		a := math.Float32frombits(uint32(alo >> shift))
		b := math.Float32frombits(uint32(ahi >> shift))
		lo |= uint64(math.Float32bits(f(a))) << shift
		hi |= uint64(math.Float32bits(f(b))) << shift
	}
	return
}

// map64f applies f to the two 64-bit float lanes.
func map64f(alo, ahi uint64, f func(float64) float64) (lo, hi uint64) {
	return math.Float64bits(f(math.Float64frombits(alo))),
		math.Float64bits(f(math.Float64frombits(ahi)))
}

// lane32f applies f to the four 32-bit float lanes of (a,b).
func lane32f(alo, ahi, blo, bhi uint64, f func(a, b float32) float32) (lo, hi uint64) {
	return lane32(alo, ahi, blo, bhi, func(a, b uint32) uint32 {
		return math.Float32bits(f(math.Float32frombits(a), math.Float32frombits(b)))
	})
}

// lane64f applies f to the two 64-bit float lanes of (a,b).
func lane64f(alo, ahi, blo, bhi uint64, f func(a, b float64) float64) (lo, hi uint64) {
	return lane64(alo, ahi, blo, bhi, func(a, b uint64) uint64 {
		return math.Float64bits(f(math.Float64frombits(a), math.Float64frombits(b)))
	})
}

// ── Packed integer operations ─────────────────────────────────────────────

func (e *Engine) ssePaddb(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return lane8(dlo, dhi, slo, shi, func(a, b uint8) uint8 { return a + b })
}
func (e *Engine) ssePaddw(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return lane16(dlo, dhi, slo, shi, func(a, b uint16) uint16 { return a + b })
}
func (e *Engine) ssePaddd(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return lane32(dlo, dhi, slo, shi, func(a, b uint32) uint32 { return a + b })
}
func (e *Engine) ssePaddq(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return lane64(dlo, dhi, slo, shi, func(a, b uint64) uint64 { return a + b })
}

func (e *Engine) ssePsubb(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return lane8(dlo, dhi, slo, shi, func(a, b uint8) uint8 { return a - b })
}
func (e *Engine) ssePsubw(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return lane16(dlo, dhi, slo, shi, func(a, b uint16) uint16 { return a - b })
}
func (e *Engine) ssePsubd(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return lane32(dlo, dhi, slo, shi, func(a, b uint32) uint32 { return a - b })
}
func (e *Engine) ssePsubq(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return lane64(dlo, dhi, slo, shi, func(a, b uint64) uint64 { return a - b })
}

// Saturating byte/word add/sub (signed and unsigned).
func saturateAddU8(a, b uint8) uint8 {
	s := uint16(a) + uint16(b)
	if s > 0xFF {
		return 0xFF
	}
	return uint8(s)
}
func saturateSubU8(a, b uint8) uint8 {
	if a < b {
		return 0
	}
	return a - b
}
func saturateAddS16(a, b int16) int16 {
	s := int32(a) + int32(b)
	if s > 0x7FFF {
		return 0x7FFF
	}
	if s < -0x8000 {
		return -0x8000
	}
	return int16(s)
}
func saturateSubS16(a, b int16) int16 {
	s := int32(a) - int32(b)
	if s > 0x7FFF {
		return 0x7FFF
	}
	if s < -0x8000 {
		return -0x8000
	}
	return int16(s)
}

func (e *Engine) ssePaddsb(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return lane8(dlo, dhi, slo, shi, func(a, b uint8) uint8 {
		s := int16(int8(a)) + int16(int8(b))
		if s > 127 {
			return 127
		}
		if s < -128 {
			return 0x80
		}
		return uint8(int8(s))
	})
}
func (e *Engine) ssePaddsw(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return lane16(dlo, dhi, slo, shi, func(a, b uint16) uint16 {
		return uint16(saturateAddS16(int16(a), int16(b)))
	})
}
func (e *Engine) ssePsubsb(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return lane8(dlo, dhi, slo, shi, func(a, b uint8) uint8 {
		s := int16(int8(a)) - int16(int8(b))
		if s > 127 {
			return 127
		}
		if s < -128 {
			return 0x80
		}
		return uint8(int8(s))
	})
}
func (e *Engine) ssePsubsw(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return lane16(dlo, dhi, slo, shi, func(a, b uint16) uint16 {
		return uint16(saturateSubS16(int16(a), int16(b)))
	})
}
func (e *Engine) ssePaddusb(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return lane8(dlo, dhi, slo, shi, saturateAddU8)
}
func (e *Engine) ssePaddusw(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return lane16(dlo, dhi, slo, shi, func(a, b uint16) uint16 {
		s := uint32(a) + uint32(b)
		if s > 0xFFFF {
			return 0xFFFF
		}
		return uint16(s)
	})
}
func (e *Engine) ssePsubusb(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return lane8(dlo, dhi, slo, shi, saturateSubU8)
}
func (e *Engine) ssePsubusw(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return lane16(dlo, dhi, slo, shi, func(a, b uint16) uint16 {
		if a < b {
			return 0
		}
		return a - b
	})
}

// Bitwise ops.
func (e *Engine) ssePand(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return dlo & slo, dhi & shi
}
func (e *Engine) ssePandn(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return ^dlo & slo, ^dhi & shi
}
func (e *Engine) ssePor(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return dlo | slo, dhi | shi
}
func (e *Engine) ssePxor(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return dlo ^ slo, dhi ^ shi
}

// PMULLW – signed 16-bit multiply, keep low 16 bits.
func (e *Engine) ssePmullw(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return lane16(dlo, dhi, slo, shi, func(a, b uint16) uint16 {
		return uint16(int16(a) * int16(b))
	})
}

// PMULHW – signed 16-bit multiply, keep high 16 bits.
func (e *Engine) ssePmulhw(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return lane16(dlo, dhi, slo, shi, func(a, b uint16) uint16 {
		return uint16(int32(int16(a)) * int32(int16(b)) >> 16)
	})
}

// PMULHUW – unsigned 16-bit multiply, keep high 16 bits.
func (e *Engine) ssePmulhuw(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return lane16(dlo, dhi, slo, shi, func(a, b uint16) uint16 {
		return uint16(uint32(a) * uint32(b) >> 16)
	})
}

// PMULLD – signed 32-bit multiply, keep low 32 bits (SSE4.1).
func (e *Engine) ssePmulld(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return lane32(dlo, dhi, slo, shi, func(a, b uint32) uint32 {
		return uint32(int32(a) * int32(b))
	})
}

// PMULUDQ – unsigned 32-bit low × 32-bit low → 64-bit product.
func (e *Engine) ssePmuludq(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	lo = (dlo & 0xFFFFFFFF) * (slo & 0xFFFFFFFF)
	hi = (dhi & 0xFFFFFFFF) * (shi & 0xFFFFFFFF)
	return
}

// PMADDWD – multiply packed signed 16-bit integers and add adjacent pairs.
func (e *Engine) ssePmaddwd(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	prod := func(hi64, lo64 uint64, shift uint) uint32 {
		a := int32(int16(lo64 >> shift))
		b := int32(int16(lo64 >> (shift + 16)))
		c := int32(int16(hi64 >> shift))
		d := int32(int16(hi64 >> (shift + 16)))
		return uint32(a*c + b*d)
	}
	lo = uint64(prod(slo, dlo, 0)) | uint64(prod(slo, dlo, 32))<<32
	hi = uint64(prod(shi, dhi, 0)) | uint64(prod(shi, dhi, 32))<<32
	return
}

// PSADBW – sum of absolute differences of 8-bit unsigned values.
func (e *Engine) ssePsadbw(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	var sumLo, sumHi uint64
	for i := 0; i < 8; i++ {
		shift := uint(i * 8)
		al, bl := uint8(dlo>>shift), uint8(slo>>shift)
		ah, bh := uint8(dhi>>shift), uint8(shi>>shift)
		if al >= bl {
			sumLo += uint64(al - bl)
		} else {
			sumLo += uint64(bl - al)
		}
		if ah >= bh {
			sumHi += uint64(ah - bh)
		} else {
			sumHi += uint64(bh - ah)
		}
	}
	return sumLo & 0xFFFF, sumHi & 0xFFFF
}

// PAVGB / PAVGW – average of unsigned bytes/words, rounded up.
func (e *Engine) ssePavgb(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return lane8(dlo, dhi, slo, shi, func(a, b uint8) uint8 {
		return uint8((uint16(a) + uint16(b) + 1) >> 1)
	})
}
func (e *Engine) ssePavgw(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return lane16(dlo, dhi, slo, shi, func(a, b uint16) uint16 {
		return uint16((uint32(a) + uint32(b) + 1) >> 1)
	})
}

// Packed min/max.
func (e *Engine) ssePminub(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return lane8(dlo, dhi, slo, shi, func(a, b uint8) uint8 {
		if a < b {
			return a
		}
		return b
	})
}
func (e *Engine) ssePmaxub(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return lane8(dlo, dhi, slo, shi, func(a, b uint8) uint8 {
		if a > b {
			return a
		}
		return b
	})
}
func (e *Engine) ssePminsw(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return lane16(dlo, dhi, slo, shi, func(a, b uint16) uint16 {
		if int16(a) < int16(b) {
			return a
		}
		return b
	})
}
func (e *Engine) ssePmaxsw(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return lane16(dlo, dhi, slo, shi, func(a, b uint16) uint16 {
		if int16(a) > int16(b) {
			return a
		}
		return b
	})
}
func (e *Engine) ssePminsb(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return lane8(dlo, dhi, slo, shi, func(a, b uint8) uint8 {
		if int8(a) < int8(b) {
			return a
		}
		return b
	})
}
func (e *Engine) ssePmaxsb(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return lane8(dlo, dhi, slo, shi, func(a, b uint8) uint8 {
		if int8(a) > int8(b) {
			return a
		}
		return b
	})
}
func (e *Engine) ssePminsd(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return lane32(dlo, dhi, slo, shi, func(a, b uint32) uint32 {
		if int32(a) < int32(b) {
			return a
		}
		return b
	})
}
func (e *Engine) ssePmaxsd(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return lane32(dlo, dhi, slo, shi, func(a, b uint32) uint32 {
		if int32(a) > int32(b) {
			return a
		}
		return b
	})
}
func (e *Engine) ssePminuw(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return lane16(dlo, dhi, slo, shi, func(a, b uint16) uint16 {
		if a < b {
			return a
		}
		return b
	})
}
func (e *Engine) ssePmaxuw(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return lane16(dlo, dhi, slo, shi, func(a, b uint16) uint16 {
		if a > b {
			return a
		}
		return b
	})
}
func (e *Engine) ssePminud(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return lane32(dlo, dhi, slo, shi, func(a, b uint32) uint32 {
		if a < b {
			return a
		}
		return b
	})
}
func (e *Engine) ssePmaxud(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return lane32(dlo, dhi, slo, shi, func(a, b uint32) uint32 {
		if a > b {
			return a
		}
		return b
	})
}

// PMULDQ – signed 32-bit × 32-bit → 64-bit (even lanes, SSE4.1).
func (e *Engine) ssePmuldq(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	lo = uint64(int64(int32(dlo)) * int64(int32(slo)))
	hi = uint64(int64(int32(dhi)) * int64(int32(shi)))
	return
}

// Packed compare: equal.
func (e *Engine) ssePcmpeqb(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	mask := func(ok bool) uint8 {
		if ok {
			return 0xFF
		}
		return 0
	}
	return lane8(dlo, dhi, slo, shi, func(a, b uint8) uint8 { return mask(a == b) })
}
func (e *Engine) ssePcmpeqw(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	mask := func(ok bool) uint16 {
		if ok {
			return 0xFFFF
		}
		return 0
	}
	return lane16(dlo, dhi, slo, shi, func(a, b uint16) uint16 { return mask(a == b) })
}
func (e *Engine) ssePcmpeqd(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	mask := func(ok bool) uint32 {
		if ok {
			return 0xFFFFFFFF
		}
		return 0
	}
	return lane32(dlo, dhi, slo, shi, func(a, b uint32) uint32 { return mask(a == b) })
}
func (e *Engine) ssePcmpeqq(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	mask := func(ok bool) uint64 {
		if ok {
			return ^uint64(0)
		}
		return 0
	}
	return lane64(dlo, dhi, slo, shi, func(a, b uint64) uint64 { return mask(a == b) })
}

// Packed compare: signed greater-than.
func (e *Engine) ssePcmpgtb(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return lane8(dlo, dhi, slo, shi, func(a, b uint8) uint8 {
		if int8(a) > int8(b) {
			return 0xFF
		}
		return 0
	})
}
func (e *Engine) ssePcmpgtw(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return lane16(dlo, dhi, slo, shi, func(a, b uint16) uint16 {
		if int16(a) > int16(b) {
			return 0xFFFF
		}
		return 0
	})
}
func (e *Engine) ssePcmpgtd(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return lane32(dlo, dhi, slo, shi, func(a, b uint32) uint32 {
		if int32(a) > int32(b) {
			return 0xFFFFFFFF
		}
		return 0
	})
}
func (e *Engine) ssePcmpgtq(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return lane64(dlo, dhi, slo, shi, func(a, b uint64) uint64 {
		if int64(a) > int64(b) {
			return ^uint64(0)
		}
		return 0
	})
}

// PTEST – bitwise AND and set ZF/CF (SSE4.1).
// ZF = (src & dst) == 0; CF = (~dst & src) == 0.
func (e *Engine) ssePtest(dlo, dhi, slo, shi uint64) {
	zf := (slo&dlo|shi&dhi) == 0
	cf := (^dlo&slo|^dhi&shi) == 0
	e.setFlag(flagZF, zf)
	e.setFlag(flagCF, cf)
	e.setFlag(flagAF, false)
	e.setFlag(flagOF, false)
	e.setFlag(flagSF, false)
	e.setFlag(flagPF, false)
}

// PMOVMSKB – byte mask: bit i = sign bit of byte i.
func ssePmovmskb(lo, hi uint64) uint32 {
	var mask uint32
	for i := 0; i < 8; i++ {
		if lo>>(uint(i*8)+7)&1 != 0 {
			mask |= 1 << uint(i)
		}
		if hi>>(uint(i*8)+7)&1 != 0 {
			mask |= 1 << uint(i+8)
		}
	}
	return mask
}

// ── Packed shift operations ───────────────────────────────────────────────

// PSLLW/PSRLW/PSRAW – shift per 16-bit lane by count from xmm/m128 or imm8.
func ssePsllw(lo, hi, count uint64) (uint64, uint64) {
	if count >= 16 {
		return 0, 0
	}
	return lane16(lo, hi, 0, 0, func(a, _ uint16) uint16 { return a << uint(count) })
}
func ssePsrlw(lo, hi, count uint64) (uint64, uint64) {
	if count >= 16 {
		return 0, 0
	}
	return lane16(lo, hi, 0, 0, func(a, _ uint16) uint16 { return a >> uint(count) })
}
func ssePsraw(lo, hi, count uint64) (uint64, uint64) {
	if count >= 16 {
		count = 15
	}
	return lane16(lo, hi, 0, 0, func(a, _ uint16) uint16 { return uint16(int16(a) >> uint(count)) })
}

// PSLLD/PSRLD/PSRAD.
func ssePslld(lo, hi, count uint64) (uint64, uint64) {
	if count >= 32 {
		return 0, 0
	}
	return lane32(lo, hi, 0, 0, func(a, _ uint32) uint32 { return a << uint(count) })
}
func ssePsrld(lo, hi, count uint64) (uint64, uint64) {
	if count >= 32 {
		return 0, 0
	}
	return lane32(lo, hi, 0, 0, func(a, _ uint32) uint32 { return a >> uint(count) })
}
func ssePsrad(lo, hi, count uint64) (uint64, uint64) {
	if count >= 32 {
		count = 31
	}
	return lane32(lo, hi, 0, 0, func(a, _ uint32) uint32 { return uint32(int32(a) >> uint(count)) })
}

// PSLLQ/PSRLQ.
func ssePsllq(lo, hi, count uint64) (uint64, uint64) {
	if count >= 64 {
		return 0, 0
	}
	return lo << uint(count), hi << uint(count)
}
func ssePsrlq(lo, hi, count uint64) (uint64, uint64) {
	if count >= 64 {
		return 0, 0
	}
	return lo >> uint(count), hi >> uint(count)
}

// PSLLDQ – shift double quadword left by imm8 bytes.
func ssePslldq(lo, hi uint64, imm uint8) (uint64, uint64) {
	n := int(imm) // byte count
	if n >= 16 {
		return 0, 0
	}
	// Treat [hi:lo] as a 128-bit little-endian integer and shift left n bytes.
	var tmp [16]byte
	copy(tmp[:8], u64ToLE(lo, 8))
	copy(tmp[8:], u64ToLE(hi, 8))
	var out [16]byte
	copy(out[n:], tmp[:16-n])
	return leToU64(out[:8]), leToU64(out[8:])
}

// PSRLDQ – shift double quadword right by imm8 bytes.
func ssePsrldq(lo, hi uint64, imm uint8) (uint64, uint64) {
	n := int(imm)
	if n >= 16 {
		return 0, 0
	}
	var tmp [16]byte
	copy(tmp[:8], u64ToLE(lo, 8))
	copy(tmp[8:], u64ToLE(hi, 8))
	var out [16]byte
	copy(out[:16-n], tmp[n:])
	return leToU64(out[:8]), leToU64(out[8:])
}

// ── Unpack / pack / shuffle ───────────────────────────────────────────────

// PUNPCKLBW – interleave low 8 bytes of dst and src.
func ssePunpcklbw(dlo, _, slo, _ uint64) (lo, hi uint64) {
	for i := 0; i < 8; i++ {
		db := uint8(dlo >> uint(i*8))
		sb := uint8(slo >> uint(i*8))
		shift := uint(i * 16)
		if shift < 64 {
			lo |= uint64(db) << shift
			lo |= uint64(sb) << (shift + 8)
		} else {
			shift -= 64
			hi |= uint64(db) << shift
			hi |= uint64(sb) << (shift + 8)
		}
	}
	return
}

// PUNPCKHBW – interleave high 8 bytes.
func ssePunpckhbw(_, dhi, _, shi uint64) (lo, hi uint64) {
	return ssePunpcklbw(dhi, 0, shi, 0)
}

// PUNPCKLWD – interleave low 4 words.
func ssePunpcklwd(dlo, _, slo, _ uint64) (lo, hi uint64) {
	for i := 0; i < 4; i++ {
		dw := uint16(dlo >> uint(i*16))
		sw := uint16(slo >> uint(i*16))
		shift := uint(i * 32)
		if shift < 64 {
			lo |= uint64(dw) << shift
			lo |= uint64(sw) << (shift + 16)
		} else {
			shift -= 64
			hi |= uint64(dw) << shift
			hi |= uint64(sw) << (shift + 16)
		}
	}
	return
}

// PUNPCKHWD.
func ssePunpckhwd(_, dhi, _, shi uint64) (lo, hi uint64) {
	return ssePunpcklwd(dhi, 0, shi, 0)
}

// PUNPCKLDQ – interleave low 2 dwords.
func ssePunpckldq(dlo, _, slo, _ uint64) (lo, hi uint64) {
	lo = (dlo & 0xFFFFFFFF) | (slo&0xFFFFFFFF)<<32
	hi = (dlo >> 32 & 0xFFFFFFFF) | (slo>>32&0xFFFFFFFF)<<32
	return
}

// PUNPCKHDQ.
func ssePunpckhdq(_, dhi, _, shi uint64) (lo, hi uint64) {
	return ssePunpckldq(dhi, 0, shi, 0)
}

// PUNPCKLQDQ – interleave low qwords.
func ssePunpcklqdq(dlo, _, slo, _ uint64) (lo, hi uint64) { return dlo, slo }

// PUNPCKHQDQ.
func ssePunpckhqdq(_, dhi, _, shi uint64) (lo, hi uint64) { return dhi, shi }

// PACKSSWB – signed saturate 8 words → 8 bytes.
func ssePacksswb(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	pack := func(a int16) uint8 {
		if a > 127 {
			return 127
		}
		if a < -128 {
			return 0x80
		}
		return uint8(int8(a))
	}
	for i := 0; i < 8; i++ {
		shift := uint(i * 16)
		var v int16
		if i < 4 {
			v = int16(dlo >> shift)
		} else {
			v = int16(dhi >> uint((i-4)*16))
		}
		lo |= uint64(pack(v)) << uint(i*8)
	}
	for i := 0; i < 8; i++ {
		shift := uint(i * 16)
		var v int16
		if i < 4 {
			v = int16(slo >> shift)
		} else {
			v = int16(shi >> uint((i-4)*16))
		}
		hi |= uint64(pack(v)) << uint(i*8)
	}
	return
}

// PACKUSWB – unsigned saturate 8 words → 8 bytes.
func ssePackuswb(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	pack := func(a int16) uint8 {
		if a < 0 {
			return 0
		}
		if a > 255 {
			return 255
		}
		return uint8(a)
	}
	for i := 0; i < 8; i++ {
		shift := uint(i * 16)
		var v int16
		if i < 4 {
			v = int16(dlo >> shift)
		} else {
			v = int16(dhi >> uint((i-4)*16))
		}
		lo |= uint64(pack(v)) << uint(i*8)
	}
	for i := 0; i < 8; i++ {
		shift := uint(i * 16)
		var v int16
		if i < 4 {
			v = int16(slo >> shift)
		} else {
			v = int16(shi >> uint((i-4)*16))
		}
		hi |= uint64(pack(v)) << uint(i*8)
	}
	return
}

// PACKSSDW – signed saturate 4 dwords → 4 words.
func ssePackssdw(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	pack := func(a int32) uint16 {
		if a > 0x7FFF {
			return 0x7FFF
		}
		if a < -0x8000 {
			return 0x8000
		}
		return uint16(int16(a))
	}
	lo = uint64(pack(int32(dlo))) | uint64(pack(int32(dlo>>32)))<<16 |
		uint64(pack(int32(dhi)))<<32 | uint64(pack(int32(dhi>>32)))<<48
	hi = uint64(pack(int32(slo))) | uint64(pack(int32(slo>>32)))<<16 |
		uint64(pack(int32(shi)))<<32 | uint64(pack(int32(shi>>32)))<<48
	return
}

// PSHUFD – shuffle 32-bit lanes within 128 bits using imm8 control.
func ssePshufd(slo, shi uint64, imm uint8) (lo, hi uint64) {
	get := func(idx int) uint32 {
		if idx < 2 {
			return uint32(slo >> uint(idx*32))
		}
		return uint32(shi >> uint((idx-2)*32))
	}
	lo = uint64(get(int(imm&3))) | uint64(get(int(imm>>2&3)))<<32
	hi = uint64(get(int(imm>>4&3))) | uint64(get(int(imm>>6&3)))<<32
	return
}

// PSHUFHW – shuffle high 4 words using imm8, low 4 words pass through.
func ssePshufhw(slo, shi uint64, imm uint8) (lo, hi uint64) {
	get := func(idx int) uint16 { return uint16(shi >> uint(idx*16)) }
	hi = uint64(get(int(imm&3))) | uint64(get(int(imm>>2&3)))<<16 |
		uint64(get(int(imm>>4&3)))<<32 | uint64(get(int(imm>>6&3)))<<48
	return slo, hi
}

// PSHUFLW – shuffle low 4 words using imm8, high 4 words pass through.
func ssePshuflw(slo, shi uint64, imm uint8) (lo, hi uint64) {
	get := func(idx int) uint16 { return uint16(slo >> uint(idx*16)) }
	lo = uint64(get(int(imm&3))) | uint64(get(int(imm>>2&3)))<<16 |
		uint64(get(int(imm>>4&3)))<<32 | uint64(get(int(imm>>6&3)))<<48
	return lo, shi
}

// SHUFPS – shuffle 32-bit floats; upper two from src, lower two from dst.
func sseShufps(dlo, dhi, slo, shi uint64, imm uint8) (lo, hi uint64) {
	getDst := func(idx int) uint32 {
		if idx < 2 {
			return uint32(dlo >> uint(idx*32))
		}
		return uint32(dhi >> uint((idx-2)*32))
	}
	getSrc := func(idx int) uint32 {
		if idx < 2 {
			return uint32(slo >> uint(idx*32))
		}
		return uint32(shi >> uint((idx-2)*32))
	}
	lo = uint64(getDst(int(imm&3))) | uint64(getDst(int(imm>>2&3)))<<32
	hi = uint64(getSrc(int(imm>>4&3))) | uint64(getSrc(int(imm>>6&3)))<<32
	return
}

// SHUFPD – shuffle 64-bit doubles.
func sseShufpd(dlo, dhi, slo, shi uint64, imm uint8) (lo, hi uint64) {
	if imm&1 != 0 {
		lo = dhi
	} else {
		lo = dlo
	}
	if imm&2 != 0 {
		hi = shi
	} else {
		hi = slo
	}
	return
}

// PSHUFB – variable byte shuffle (SSSE3 / 0F 38 00).
// Each byte of mask selects which byte of src to place there; bit 7 → 0.
func ssePshufb(dlo, dhi, mlo, mhi uint64) (lo, hi uint64) {
	src := func(i int) byte {
		if i < 8 {
			return byte(dlo >> uint(i*8))
		}
		return byte(dhi >> uint((i-8)*8))
	}
	set := func(dst *uint64, idx int, v byte) {
		*dst |= uint64(v) << uint(idx*8)
	}
	for i := 0; i < 8; i++ {
		m := byte(mlo >> uint(i*8))
		var v byte
		if m&0x80 == 0 {
			v = src(int(m & 0x0F))
		}
		set(&lo, i, v)
	}
	for i := 0; i < 8; i++ {
		m := byte(mhi >> uint(i*8))
		var v byte
		if m&0x80 == 0 {
			v = src(int(m & 0x0F))
		}
		set(&hi, i, v)
	}
	return
}

// PALIGNR – concatenate and shift right by imm8 bytes.
func ssePalignr(dlo, dhi, slo, shi uint64, imm uint8) (lo, hi uint64) {
	n := int(imm)
	if n >= 32 {
		return 0, 0
	}
	// Build 32-byte [src | dst] and extract 16 bytes at offset n.
	var tmp [32]byte
	copy(tmp[:8], u64ToLE(slo, 8))
	copy(tmp[8:16], u64ToLE(shi, 8))
	copy(tmp[16:24], u64ToLE(dlo, 8))
	copy(tmp[24:32], u64ToLE(dhi, 8))
	slice := tmp[n : n+16]
	return leToU64(slice[:8]), leToU64(slice[8:])
}

// PINSRB/PINSRW/PINSRD/PINSRQ – insert one integer lane.
func ssePinsrb(dlo, dhi uint64, v uint8, imm uint8) (lo, hi uint64) {
	pos := int(imm & 0xF)
	shift := uint(pos * 8)
	if pos < 8 {
		lo = (dlo &^ (0xFF << shift)) | uint64(v)<<shift
		hi = dhi
	} else {
		shift -= 64
		lo = dlo
		hi = (dhi &^ (0xFF << shift)) | uint64(v)<<shift
	}
	return
}
func ssePinsrw(dlo, dhi uint64, v uint16, imm uint8) (lo, hi uint64) {
	pos := int(imm & 7)
	shift := uint(pos * 16)
	if pos < 4 {
		lo = (dlo &^ (0xFFFF << shift)) | uint64(v)<<shift
		hi = dhi
	} else {
		shift -= 64
		lo = dlo
		hi = (dhi &^ (0xFFFF << shift)) | uint64(v)<<shift
	}
	return
}
func ssePinsrd(dlo, dhi uint64, v uint32, imm uint8) (lo, hi uint64) {
	pos := int(imm & 3)
	shift := uint(pos * 32)
	if pos < 2 {
		lo = (dlo &^ (0xFFFFFFFF << shift)) | uint64(v)<<shift
		hi = dhi
	} else {
		shift -= 64
		lo = dlo
		hi = (dhi &^ (0xFFFFFFFF << shift)) | uint64(v)<<shift
	}
	return
}
func ssePinsrq(dlo, dhi uint64, v uint64, imm uint8) (lo, hi uint64) {
	if imm&1 == 0 {
		return v, dhi
	}
	return dlo, v
}

// PEXTRB/PEXTRW/PEXTRD/PEXTRQ.
func ssePextrb(lo, hi uint64, imm uint8) uint8 {
	pos := int(imm & 0xF)
	if pos < 8 {
		return uint8(lo >> uint(pos*8))
	}
	return uint8(hi >> uint((pos-8)*8))
}
func ssePextrw(lo, hi uint64, imm uint8) uint16 {
	pos := int(imm & 7)
	if pos < 4 {
		return uint16(lo >> uint(pos*16))
	}
	return uint16(hi >> uint((pos-4)*16))
}
func ssePextrd(lo, hi uint64, imm uint8) uint32 {
	pos := int(imm & 3)
	if pos < 2 {
		return uint32(lo >> uint(pos*32))
	}
	return uint32(hi >> uint((pos-2)*32))
}
func ssePextrq(lo, hi uint64, imm uint8) uint64 {
	if imm&1 == 0 {
		return lo
	}
	return hi
}

// MOVMSKPS – 4-bit mask from sign bits of 4 floats.
func sseMovmskps(lo, hi uint64) uint32 {
	return uint32(lo>>31&1) | uint32(lo>>62&2) | uint32(hi>>29&4) | uint32(hi>>60&8)
}

// MOVMSKPD – 2-bit mask from sign bits of 2 doubles.
func sseMovmskpd(lo, hi uint64) uint32 {
	return uint32(lo>>63) | uint32(hi>>62&2)
}

// ── Packed float operations ───────────────────────────────────────────────

func (e *Engine) sseAddps(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return lane32f(dlo, dhi, slo, shi, func(a, b float32) float32 { return a + b })
}
func (e *Engine) sseSubps(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return lane32f(dlo, dhi, slo, shi, func(a, b float32) float32 { return a - b })
}
func (e *Engine) sseMulps(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return lane32f(dlo, dhi, slo, shi, func(a, b float32) float32 { return a * b })
}
func (e *Engine) sseDivps(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return lane32f(dlo, dhi, slo, shi, func(a, b float32) float32 { return a / b })
}
func (e *Engine) sseSqrtps(lo, hi uint64) (uint64, uint64) {
	return map32f(lo, hi, func(a float32) float32 { return float32(math.Sqrt(float64(a))) })
}
func (e *Engine) sseRsqrtps(lo, hi uint64) (uint64, uint64) {
	return map32f(lo, hi, func(a float32) float32 { return float32(1.0 / math.Sqrt(float64(a))) })
}
func (e *Engine) sseRcpps(lo, hi uint64) (uint64, uint64) {
	return map32f(lo, hi, func(a float32) float32 { return 1.0 / a })
}
func (e *Engine) sseMinps(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return lane32f(dlo, dhi, slo, shi, func(a, b float32) float32 {
		if math.IsNaN(float64(b)) || b < a {
			return b
		}
		return a
	})
}
func (e *Engine) sseMaxps(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return lane32f(dlo, dhi, slo, shi, func(a, b float32) float32 {
		if math.IsNaN(float64(b)) || b > a {
			return b
		}
		return a
	})
}
func (e *Engine) sseAndps(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return dlo & slo, dhi & shi
}
func (e *Engine) sseAndnps(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return ^dlo & slo, ^dhi & shi
}
func (e *Engine) sseOrps(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return dlo | slo, dhi | shi
}
func (e *Engine) sseXorps(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return dlo ^ slo, dhi ^ shi
}

// CMPPS – packed float compare, imm8 selects predicate.
func (e *Engine) sseCmpps(dlo, dhi, slo, shi uint64, imm uint8) (lo, hi uint64) {
	pred := cmpFloatPred(imm & 7)
	return lane32f(dlo, dhi, slo, shi, func(a, b float32) float32 {
		if pred(float64(a), float64(b)) {
			return math.Float32frombits(0xFFFFFFFF)
		}
		return 0
	})
}

// cmpFloatPred returns a comparison predicate for CMPSS/CMPPS/CMPSD/CMPPD.
func cmpFloatPred(imm uint8) func(a, b float64) bool {
	switch imm & 7 {
	case 0: // EQ
		return func(a, b float64) bool { return a == b }
	case 1: // LT
		return func(a, b float64) bool { return a < b }
	case 2: // LE
		return func(a, b float64) bool { return a <= b }
	case 3: // UNORD
		return func(a, b float64) bool { return math.IsNaN(a) || math.IsNaN(b) }
	case 4: // NEQ
		return func(a, b float64) bool { return a != b || math.IsNaN(a) || math.IsNaN(b) }
	case 5: // NLT
		return func(a, b float64) bool { return !(a < b) }
	case 6: // NLE
		return func(a, b float64) bool { return !(a <= b) }
	case 7: // ORD
		return func(a, b float64) bool { return !math.IsNaN(a) && !math.IsNaN(b) }
	}
	return func(a, b float64) bool { return false }
}

// Packed double ops.
func (e *Engine) sseAddpd(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return lane64f(dlo, dhi, slo, shi, func(a, b float64) float64 { return a + b })
}
func (e *Engine) sseSubpd(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return lane64f(dlo, dhi, slo, shi, func(a, b float64) float64 { return a - b })
}
func (e *Engine) sseMulpd(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return lane64f(dlo, dhi, slo, shi, func(a, b float64) float64 { return a * b })
}
func (e *Engine) sseDivpd(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return lane64f(dlo, dhi, slo, shi, func(a, b float64) float64 { return a / b })
}
func (e *Engine) sseSqrtpd(lo, hi uint64) (uint64, uint64) {
	return map64f(lo, hi, math.Sqrt)
}
func (e *Engine) sseMinpd(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return lane64f(dlo, dhi, slo, shi, func(a, b float64) float64 {
		if math.IsNaN(b) || b < a {
			return b
		}
		return a
	})
}
func (e *Engine) sseMaxpd(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	return lane64f(dlo, dhi, slo, shi, func(a, b float64) float64 {
		if math.IsNaN(b) || b > a {
			return b
		}
		return a
	})
}
func (e *Engine) sseCmppd(dlo, dhi, slo, shi uint64, imm uint8) (lo, hi uint64) {
	pred := cmpFloatPred(imm & 7)
	return lane64f(dlo, dhi, slo, shi, func(a, b float64) float64 {
		if pred(a, b) {
			return math.Float64frombits(^uint64(0))
		}
		return 0
	})
}

// HADDPS – horizontal add adjacent float pairs.
func sseHaddps(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	a0 := math.Float32frombits(uint32(dlo))
	a1 := math.Float32frombits(uint32(dlo >> 32))
	a2 := math.Float32frombits(uint32(dhi))
	a3 := math.Float32frombits(uint32(dhi >> 32))
	b0 := math.Float32frombits(uint32(slo))
	b1 := math.Float32frombits(uint32(slo >> 32))
	b2 := math.Float32frombits(uint32(shi))
	b3 := math.Float32frombits(uint32(shi >> 32))
	lo = uint64(math.Float32bits(a0+a1)) | uint64(math.Float32bits(a2+a3))<<32
	hi = uint64(math.Float32bits(b0+b1)) | uint64(math.Float32bits(b2+b3))<<32
	return
}

// HADDPD – horizontal add adjacent double pairs.
func sseHaddpd(dlo, dhi, slo, shi uint64) (lo, hi uint64) {
	a0 := math.Float64frombits(dlo)
	a1 := math.Float64frombits(dhi)
	b0 := math.Float64frombits(slo)
	b1 := math.Float64frombits(shi)
	return math.Float64bits(a0 + a1), math.Float64bits(b0 + b1)
}

// ── Scalar float operations ───────────────────────────────────────────────
// Scalar ops touch only the lowest lane; higher lanes of the destination
// are merged from the destination operand (for SSE) or zeroed (for AVX).

// sseAddss returns (dst.lo with low float32 replaced by dst[0]+src[0], dst.hi).
func sseAddss(dlo, dhi, slo, _ uint64) (lo, hi uint64) {
	a := math.Float32frombits(uint32(dlo))
	b := math.Float32frombits(uint32(slo))
	return (dlo &^ 0xFFFFFFFF) | uint64(math.Float32bits(a+b)), dhi
}
func sseSubss(dlo, dhi, slo, _ uint64) (lo, hi uint64) {
	a := math.Float32frombits(uint32(dlo))
	b := math.Float32frombits(uint32(slo))
	return (dlo &^ 0xFFFFFFFF) | uint64(math.Float32bits(a-b)), dhi
}
func sseMulss(dlo, dhi, slo, _ uint64) (lo, hi uint64) {
	a := math.Float32frombits(uint32(dlo))
	b := math.Float32frombits(uint32(slo))
	return (dlo &^ 0xFFFFFFFF) | uint64(math.Float32bits(a*b)), dhi
}
func sseDivss(dlo, dhi, slo, _ uint64) (lo, hi uint64) {
	a := math.Float32frombits(uint32(dlo))
	b := math.Float32frombits(uint32(slo))
	return (dlo &^ 0xFFFFFFFF) | uint64(math.Float32bits(a/b)), dhi
}
func sseSqrtss(dlo, dhi, _ uint64) (lo, hi uint64) {
	a := math.Float32frombits(uint32(dlo))
	r := float32(math.Sqrt(float64(a)))
	return (dlo &^ 0xFFFFFFFF) | uint64(math.Float32bits(r)), dhi
}
func sseRsqrtss(dlo, dhi, _ uint64) (lo, hi uint64) {
	a := math.Float32frombits(uint32(dlo))
	r := float32(1.0 / math.Sqrt(float64(a)))
	return (dlo &^ 0xFFFFFFFF) | uint64(math.Float32bits(r)), dhi
}
func sseRcpss(dlo, dhi, _ uint64) (lo, hi uint64) {
	a := math.Float32frombits(uint32(dlo))
	return (dlo &^ 0xFFFFFFFF) | uint64(math.Float32bits(1.0/a)), dhi
}
func sseMinss(dlo, dhi, slo, _ uint64) (lo, hi uint64) {
	a := math.Float32frombits(uint32(dlo))
	b := math.Float32frombits(uint32(slo))
	var r float32
	if math.IsNaN(float64(b)) || b < a {
		r = b
	} else {
		r = a
	}
	return (dlo &^ 0xFFFFFFFF) | uint64(math.Float32bits(r)), dhi
}
func sseMaxss(dlo, dhi, slo, _ uint64) (lo, hi uint64) {
	a := math.Float32frombits(uint32(dlo))
	b := math.Float32frombits(uint32(slo))
	var r float32
	if math.IsNaN(float64(b)) || b > a {
		r = b
	} else {
		r = a
	}
	return (dlo &^ 0xFFFFFFFF) | uint64(math.Float32bits(r)), dhi
}
func sseCmpss(dlo, dhi, slo, _ uint64, imm uint8) (lo, hi uint64) {
	a := math.Float32frombits(uint32(dlo))
	b := math.Float32frombits(uint32(slo))
	pred := cmpFloatPred(imm & 7)
	var r uint32
	if pred(float64(a), float64(b)) {
		r = 0xFFFFFFFF
	}
	return (dlo &^ 0xFFFFFFFF) | uint64(r), dhi
}

// Scalar double ops.
func sseAddsd(dlo, dhi, slo, _ uint64) (lo, hi uint64) {
	a, b := math.Float64frombits(dlo), math.Float64frombits(slo)
	return math.Float64bits(a + b), dhi
}
func sseSubsd(dlo, dhi, slo, _ uint64) (lo, hi uint64) {
	a, b := math.Float64frombits(dlo), math.Float64frombits(slo)
	return math.Float64bits(a - b), dhi
}
func sseMulsd(dlo, dhi, slo, _ uint64) (lo, hi uint64) {
	a, b := math.Float64frombits(dlo), math.Float64frombits(slo)
	return math.Float64bits(a * b), dhi
}
func sseDivsd(dlo, dhi, slo, _ uint64) (lo, hi uint64) {
	a, b := math.Float64frombits(dlo), math.Float64frombits(slo)
	return math.Float64bits(a / b), dhi
}
func sseSqrtsd(dlo, dhi, _ uint64) (lo, hi uint64) {
	a := math.Float64frombits(dlo)
	return math.Float64bits(math.Sqrt(a)), dhi
}
func sseMinsd(dlo, dhi, slo, _ uint64) (lo, hi uint64) {
	a, b := math.Float64frombits(dlo), math.Float64frombits(slo)
	if math.IsNaN(b) || b < a {
		return math.Float64bits(b), dhi
	}
	return math.Float64bits(a), dhi
}
func sseMaxsd(dlo, dhi, slo, _ uint64) (lo, hi uint64) {
	a, b := math.Float64frombits(dlo), math.Float64frombits(slo)
	if math.IsNaN(b) || b > a {
		return math.Float64bits(b), dhi
	}
	return math.Float64bits(a), dhi
}
func sseCmpsd(dlo, dhi, slo, _ uint64, imm uint8) (lo, hi uint64) {
	a, b := math.Float64frombits(dlo), math.Float64frombits(slo)
	pred := cmpFloatPred(imm & 7)
	var r uint64
	if pred(a, b) {
		r = ^uint64(0)
	}
	return r, dhi
}

// ── COMISS / UCOMISS / COMISD / UCOMISD ──────────────────────────────────
// These compare scalar floats and set ZF/PF/CF in EFLAGS.

func (e *Engine) sseComiss(dlo, slo uint64) {
	a := math.Float32frombits(uint32(dlo))
	b := math.Float32frombits(uint32(slo))
	e.setFlag(flagOF, false)
	e.setFlag(flagSF, false)
	e.setFlag(flagAF, false)
	if math.IsNaN(float64(a)) || math.IsNaN(float64(b)) {
		e.setFlag(flagZF, true)
		e.setFlag(flagPF, true)
		e.setFlag(flagCF, true)
	} else if a < b {
		e.setFlag(flagZF, false)
		e.setFlag(flagPF, false)
		e.setFlag(flagCF, true)
	} else if a == b {
		e.setFlag(flagZF, true)
		e.setFlag(flagPF, false)
		e.setFlag(flagCF, false)
	} else { // a > b
		e.setFlag(flagZF, false)
		e.setFlag(flagPF, false)
		e.setFlag(flagCF, false)
	}
}

func (e *Engine) sseComisd(dlo, slo uint64) {
	a := math.Float64frombits(dlo)
	b := math.Float64frombits(slo)
	e.setFlag(flagOF, false)
	e.setFlag(flagSF, false)
	e.setFlag(flagAF, false)
	if math.IsNaN(a) || math.IsNaN(b) {
		e.setFlag(flagZF, true)
		e.setFlag(flagPF, true)
		e.setFlag(flagCF, true)
	} else if a < b {
		e.setFlag(flagZF, false)
		e.setFlag(flagPF, false)
		e.setFlag(flagCF, true)
	} else if a == b {
		e.setFlag(flagZF, true)
		e.setFlag(flagPF, false)
		e.setFlag(flagCF, false)
	} else {
		e.setFlag(flagZF, false)
		e.setFlag(flagPF, false)
		e.setFlag(flagCF, false)
	}
}

// ── Conversion operations ─────────────────────────────────────────────────

// CVTSI2SS – integer (32 or 64 bit) → scalar float32, merged into dst.
func sseCvtsi2ss(dlo, dhi uint64, intVal int64) (lo, hi uint64) {
	return (dlo &^ 0xFFFFFFFF) | uint64(math.Float32bits(float32(intVal))), dhi
}

// CVTSI2SD – integer → scalar float64, merged into dst.
func sseCvtsi2sd(_, dhi uint64, intVal int64) (lo, hi uint64) {
	return math.Float64bits(float64(intVal)), dhi
}

// CVTSS2SD – scalar float32 → float64, merged into dst.
func sseCvtss2sd(dlo, dhi, slo, _ uint64) (lo, hi uint64) {
	_ = dlo
	a := math.Float32frombits(uint32(slo))
	return math.Float64bits(float64(a)), dhi
}

// CVTSD2SS – scalar float64 → float32, merged into dst.
func sseCvtsd2ss(dlo, dhi, slo, _ uint64) (lo, hi uint64) {
	a := math.Float64frombits(slo)
	return (dlo &^ 0xFFFFFFFF) | uint64(math.Float32bits(float32(a))), dhi
}

// CVTTSS2SI – truncating scalar float32 → integer (32 or 64 bit).
func sseCvttss2si(slo uint64) int64 {
	return int64(math.Trunc(float64(math.Float32frombits(uint32(slo)))))
}

// CVTTSD2SI – truncating scalar float64 → integer.
func sseCvttsd2si(slo uint64) int64 {
	return int64(math.Trunc(math.Float64frombits(slo)))
}

// CVTSS2SI – rounding scalar float32 → integer (round-to-nearest).
func sseCvtss2si(slo uint64) int64 {
	return int64(math.RoundToEven(float64(math.Float32frombits(uint32(slo)))))
}

// CVTSD2SI – rounding scalar float64 → integer.
func sseCvtsd2si(slo uint64) int64 {
	return int64(math.RoundToEven(math.Float64frombits(slo)))
}

// CVTDQ2PS – packed int32 → packed float32.
func sseCvtdq2ps(slo, shi uint64) (lo, hi uint64) {
	return lane32(slo, shi, 0, 0, func(a, _ uint32) uint32 {
		return math.Float32bits(float32(int32(a)))
	})
}

// CVTTPS2DQ – truncating packed float32 → packed int32.
func sseCvttps2dq(slo, shi uint64) (lo, hi uint64) {
	return lane32(slo, shi, 0, 0, func(a, _ uint32) uint32 {
		f := math.Float32frombits(a)
		if math.IsNaN(float64(f)) || float64(f) >= float64(1<<31) || float64(f) < float64(-1<<31) {
			return 0x80000000
		}
		return uint32(int32(f))
	})
}

// CVTPS2DQ – round-to-nearest packed float32 → packed int32.
func sseCvtps2dq(slo, shi uint64) (lo, hi uint64) {
	return lane32(slo, shi, 0, 0, func(a, _ uint32) uint32 {
		f := float64(math.Float32frombits(a))
		r := math.RoundToEven(f)
		if math.IsNaN(f) || r >= float64(1<<31) || r < float64(-1<<31) {
			return 0x80000000
		}
		return uint32(int32(r))
	})
}

// CVTPS2PD – low 2 float32 lanes → 2 float64 lanes.
func sseCvtps2pd(slo, _ uint64) (lo, hi uint64) {
	a := math.Float32frombits(uint32(slo))
	b := math.Float32frombits(uint32(slo >> 32))
	return math.Float64bits(float64(a)), math.Float64bits(float64(b))
}

// CVTPD2PS – 2 float64 → 2 float32, upper 2 lanes zeroed.
func sseCvtpd2ps(slo, shi uint64) (lo, hi uint64) {
	a := float32(math.Float64frombits(slo))
	b := float32(math.Float64frombits(shi))
	return uint64(math.Float32bits(a)) | uint64(math.Float32bits(b))<<32, 0
}

// CVTPD2DQ – round-to-nearest 2 float64 → 2 int32, upper 2 zeroed.
func sseCvtpd2dq(slo, shi uint64) (lo, hi uint64) {
	a := int32(math.RoundToEven(math.Float64frombits(slo)))
	b := int32(math.RoundToEven(math.Float64frombits(shi)))
	return uint64(uint32(a)) | uint64(uint32(b))<<32, 0
}

// CVTTPD2DQ – truncating 2 float64 → 2 int32, upper 2 zeroed.
func sseCvttpd2dq(slo, shi uint64) (lo, hi uint64) {
	a := int32(math.Trunc(math.Float64frombits(slo)))
	b := int32(math.Trunc(math.Float64frombits(shi)))
	return uint64(uint32(a)) | uint64(uint32(b))<<32, 0
}

// CVTDQ2PD – low 2 int32 → 2 float64.
func sseCvtdq2pd(slo, _ uint64) (lo, hi uint64) {
	a, b := int32(slo), int32(slo>>32)
	return math.Float64bits(float64(a)), math.Float64bits(float64(b))
}

// ── AVX 256-bit helpers ───────────────────────────────────────────────────

// applyLane32fYMM applies a float32 binary op to all 8 lanes.
func applyLane32fYMM(alo, ahi, blo, bhi, clo, chi, dlo, dhi uint64,
	f func(a, b float32) float32,
) (r0, r1, r2, r3 uint64) {
	r0, r1 = lane32f(alo, ahi, blo, bhi, f)
	r2, r3 = lane32f(clo, chi, dlo, dhi, f)
	return
}

// applyLane64fYMM applies a float64 binary op to all 4 lanes.
func applyLane64fYMM(alo, ahi, blo, bhi, clo, chi, dlo, dhi uint64,
	f func(a, b float64) float64,
) (r0, r1, r2, r3 uint64) {
	r0, r1 = lane64f(alo, ahi, blo, bhi, f)
	r2, r3 = lane64f(clo, chi, dlo, dhi, f)
	return
}

// VBROADCASTSS – broadcast one float32 to all 8 YMM lanes.
func sseVbroadcastss(src uint32, L bool) (lo, hi, hi0, hi1 uint64) {
	v := uint64(src) | uint64(src)<<32
	lo, hi = v, v
	if L {
		hi0, hi1 = v, v
	}
	return
}

// VBROADCASTSD – broadcast one float64 to all 4 YMM lanes.
func sseVbroadcastsd(src uint64) (lo, hi, hi0, hi1 uint64) {
	return src, src, src, src
}

// VPERM2F128 – select and swap 128-bit lanes.
func sseVperm2f128(
	dlo, dhi, d2lo, d2hi,
	slo, shi, s2lo, s2hi uint64,
	imm uint8,
) (lo, hi, hi0, hi1 uint64) {
	srcs := [4][2]uint64{{dlo, dhi}, {d2lo, d2hi}, {slo, shi}, {s2lo, s2hi}}
	pick := func(ctrl uint8) (uint64, uint64) {
		if ctrl&8 != 0 {
			return 0, 0
		}
		idx := ctrl & 3
		return srcs[idx][0], srcs[idx][1]
	}
	lo, hi = pick(imm & 0x0F)
	hi0, hi1 = pick(imm >> 4)
	return
}

// VINSERTF128 – insert 128-bit lane into YMM.
func sseVinsertf128(
	dlo, dhi, d2lo, d2hi, slo, shi uint64,
	imm uint8,
) (lo, hi, hi0, hi1 uint64) {
	if imm&1 == 0 {
		return slo, shi, d2lo, d2hi
	}
	return dlo, dhi, slo, shi
}

// VEXTRACTF128 – extract 128-bit lane from YMM.
func sseVextractf128(
	dlo, dhi, d2lo, d2hi uint64,
	imm uint8,
) (lo, hi uint64) {
	if imm&1 == 0 {
		return dlo, dhi
	}
	return d2lo, d2hi
}

// ── INSERTPS (SSE4.1) ─────────────────────────────────────────────────────

// sseInsertps implements INSERTPS xmm, xmm/m32, imm8.
// imm8: [7:6]=src count_s (which float32 of src), [5:4]=dest count_d, [3:0]=zmask.
func sseInsertps(dlo, dhi uint64, srcF uint32, imm uint8) (lo, hi uint64) {
	// Place srcF at lane count_d.
	countD := int(imm >> 4 & 3)
	shift := uint(countD * 32)
	if countD < 2 {
		lo = (dlo &^ (0xFFFFFFFF << shift)) | uint64(srcF)<<shift
		hi = dhi
	} else {
		shift -= 64
		lo = dlo
		hi = (dhi &^ (0xFFFFFFFF << shift)) | uint64(srcF)<<shift
	}
	// Apply zero mask.
	for bit := 0; bit < 4; bit++ {
		if imm>>uint(bit)&1 != 0 {
			s := uint(bit * 32)
			if bit < 2 {
				lo &^= 0xFFFFFFFF << s
			} else {
				hi &^= 0xFFFFFFFF << uint(s-64)
			}
		}
	}
	return
}

// ── DPPS / DPPD (SSE4.1) ─────────────────────────────────────────────────

func sseDpps(dlo, dhi, slo, shi uint64, imm uint8) (lo, hi uint64) {
	const mask = 0xFFFFFFFF
	getF := func(v uint64, i int) float32 {
		return math.Float32frombits(uint32(v >> uint(i*32)))
	}
	ds := [4]float32{getF(dlo, 0), getF(dlo, 1), getF(dhi, 0), getF(dhi, 1)}
	ss := [4]float32{getF(slo, 0), getF(slo, 1), getF(shi, 0), getF(shi, 1)}
	var dp float32
	for i := 0; i < 4; i++ {
		if imm>>(uint(i)+4)&1 != 0 {
			dp += ds[i] * ss[i]
		}
	}
	var r [4]uint32
	for i := 0; i < 4; i++ {
		if imm>>uint(i)&1 != 0 {
			r[i] = math.Float32bits(dp)
		}
	}
	lo = uint64(r[0]) | uint64(r[1])<<32
	hi = uint64(r[2]) | uint64(r[3])<<32
	_ = mask
	return
}

func sseDppd(dlo, dhi, slo, shi uint64, imm uint8) (lo, hi uint64) {
	a0 := math.Float64frombits(dlo)
	a1 := math.Float64frombits(dhi)
	b0 := math.Float64frombits(slo)
	b1 := math.Float64frombits(shi)
	var dp float64
	if imm&0x10 != 0 {
		dp += a0 * b0
	}
	if imm&0x20 != 0 {
		dp += a1 * b1
	}
	var r [2]uint64
	if imm&1 != 0 {
		r[0] = math.Float64bits(dp)
	}
	if imm&2 != 0 {
		r[1] = math.Float64bits(dp)
	}
	return r[0], r[1]
}

// ── ROUNDSS / ROUNDSD / ROUNDPS / ROUNDPD (SSE4.1) ───────────────────────
//
// imm8 [1:0]: rounding mode  0=nearest, 1=down, 2=up, 3=truncate
// imm8 [2]:   use MXCSR rounding mode (we ignore this, always use imm)

func roundF64(f float64, imm uint8) float64 {
	switch imm & 3 {
	case 0:
		return math.RoundToEven(f)
	case 1:
		return math.Floor(f)
	case 2:
		return math.Ceil(f)
	default:
		return math.Trunc(f)
	}
}

func roundF32(f float32, imm uint8) float32 {
	return float32(roundF64(float64(f), imm))
}

func sseRoundss(dlo, dhi uint64, imm uint8) (lo, hi uint64) {
	r := roundF32(math.Float32frombits(uint32(dlo)), imm)
	return (dlo &^ 0xFFFFFFFF) | uint64(math.Float32bits(r)), dhi
}
func sseRoundsd(dlo, dhi uint64, imm uint8) (lo, hi uint64) {
	r := roundF64(math.Float64frombits(dlo), imm)
	return math.Float64bits(r), dhi
}
func sseRoundps(lo, hi uint64, imm uint8) (uint64, uint64) {
	return map32f(lo, hi, func(a float32) float32 { return roundF32(a, imm) })
}
func sseRoundpd(lo, hi uint64, imm uint8) (uint64, uint64) {
	return map64f(lo, hi, func(a float64) float64 { return roundF64(a, imm) })
}

// ── Execution helpers for the decode/execute layer ────────────────────────

// execXMM reads two XMM register-or-memory operands, calls f, and writes
// the result back to dst.  zeroUpper applies the VEX zero-upper rule.
func (e *Engine) execXMM(
	dst, src operand,
	zeroUpper bool,
	f func(dlo, dhi, slo, shi uint64) (lo, hi uint64),
) error {
	dlo, dhi, err := e.readXMMOp(dst)
	if err != nil {
		return err
	}
	slo, shi, err := e.readXMMOp(src)
	if err != nil {
		return err
	}
	rlo, rhi := f(dlo, dhi, slo, shi)
	return e.writeXMMOp(dst, rlo, rhi, zeroUpper)
}

// execXMM3 is for 3-operand VEX instructions: result = f(src1, src2).
// dst = regOperand pointing to the destination XMM.
func (e *Engine) execXMM3(
	dst operand, src1Reg int, src2 operand,
	zeroUpper bool,
	f func(s1lo, s1hi, s2lo, s2hi uint64) (lo, hi uint64),
) error {
	s1lo, s1hi := e.regs.readXMM(src1Reg)
	s2lo, s2hi, err := e.readXMMOp(src2)
	if err != nil {
		return err
	}
	rlo, rhi := f(s1lo, s1hi, s2lo, s2hi)
	return e.writeXMMOp(dst, rlo, rhi, zeroUpper)
}

// execYMM reads two YMM operands, calls f, and writes the result.
func (e *Engine) execYMM(
	dst, src operand,
	f func(dlo, dhi, dhi0, dhi1, slo, shi, shi0, shi1 uint64) (lo, hi, hi0, hi1 uint64),
) error {
	dlo, dhi, dhi0, dhi1, err := e.readYMMOp(dst)
	if err != nil {
		return err
	}
	slo, shi, shi0, shi1, err := e.readYMMOp(src)
	if err != nil {
		return err
	}
	rlo, rhi, rhi0, rhi1 := f(dlo, dhi, dhi0, dhi1, slo, shi, shi0, shi1)
	return e.writeYMMOp(dst, rlo, rhi, rhi0, rhi1)
}

// execYMM3 is for 3-operand VEX 256-bit instructions.
func (e *Engine) execYMM3(
	dst operand, src1Reg int, src2 operand,
	f func(s1lo, s1hi, s1hi0, s1hi1, s2lo, s2hi, s2hi0, s2hi1 uint64) (lo, hi, hi0, hi1 uint64),
) error {
	s1lo, s1hi, s1hi0, s1hi1 := e.regs.readYMM(src1Reg)
	s2lo, s2hi, s2hi0, s2hi1, err := e.readYMMOp(src2)
	if err != nil {
		return err
	}
	rlo, rhi, rhi0, rhi1 := f(s1lo, s1hi, s1hi0, s1hi1, s2lo, s2hi, s2hi0, s2hi1)
	return e.writeYMMOp(dst, rlo, rhi, rhi0, rhi1)
}

// errSSEUnsupported is returned for an otherwise structurally valid SSE
// opcode that we haven't implemented yet.
func errSSEUnsupported(what string) error {
	return fmt.Errorf("cpu: SSE/AVX: %s not implemented", what)
}
