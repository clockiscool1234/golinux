package cpu

import (
	"math"
	"testing"
)

// ── helper: XMM register readers ──────────────────────────────────────────

func xmmF32(e *Engine, n int) [4]float32 {
	lo, hi, _ := e.RegReadXMM(n)
	return [4]float32{
		math.Float32frombits(uint32(lo)),
		math.Float32frombits(uint32(lo >> 32)),
		math.Float32frombits(uint32(hi)),
		math.Float32frombits(uint32(hi >> 32)),
	}
}

func xmmF64(e *Engine, n int) [2]float64 {
	lo, hi, _ := e.RegReadXMM(n)
	return [2]float64{math.Float64frombits(lo), math.Float64frombits(hi)}
}

func xmmU32(e *Engine, n int) [4]uint32 {
	lo, hi, _ := e.RegReadXMM(n)
	return [4]uint32{uint32(lo), uint32(lo >> 32), uint32(hi), uint32(hi >> 32)}
}

func xmmU16(e *Engine, n int) [8]uint16 {
	lo, hi, _ := e.RegReadXMM(n)
	var r [8]uint16
	for i := 0; i < 4; i++ {
		r[i] = uint16(lo >> uint(i*16))
		r[i+4] = uint16(hi >> uint(i*16))
	}
	return r
}

func xmmU8(e *Engine, n int) [16]uint8 {
	lo, hi, _ := e.RegReadXMM(n)
	var r [16]uint8
	for i := 0; i < 8; i++ {
		r[i] = uint8(lo >> uint(i*8))
		r[i+8] = uint8(hi >> uint(i*8))
	}
	return r
}

// setXMMF32 loads four float32 values into XMM[n].
func setXMMF32(e *Engine, n int, a, b, c, d float32) {
	lo := uint64(math.Float32bits(a)) | uint64(math.Float32bits(b))<<32
	hi := uint64(math.Float32bits(c)) | uint64(math.Float32bits(d))<<32
	e.regs.writeXMM(n, lo, hi)
}

// setXMMF64 loads two float64 values into XMM[n].
func setXMMF64(e *Engine, n int, a, b float64) {
	e.regs.writeXMM(n, math.Float64bits(a), math.Float64bits(b))
}

// setXMMU32 loads four uint32 values into XMM[n].
func setXMMU32(e *Engine, n int, a, b, c, d uint32) {
	lo := uint64(a) | uint64(b)<<32
	hi := uint64(c) | uint64(d)<<32
	e.regs.writeXMM(n, lo, hi)
}

// newSSEEngine creates an Engine (no code mapping needed for pure-helper tests).
func newSSEEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := NewEngine()
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// ── Register accessor tests ────────────────────────────────────────────────

func TestRegReadWriteXMM(t *testing.T) {
	e := newSSEEngine(t)
	if err := e.RegWriteXMM(5, 0xDEADBEEF, 0xCAFEBABE); err != nil {
		t.Fatal(err)
	}
	lo, hi, err := e.RegReadXMM(5)
	if err != nil || lo != 0xDEADBEEF || hi != 0xCAFEBABE {
		t.Fatalf("got (%x, %x, %v)", lo, hi, err)
	}
}

func TestRegReadWriteYMM(t *testing.T) {
	e := newSSEEngine(t)
	if err := e.RegWriteYMM(3, 1, 2, 3, 4); err != nil {
		t.Fatal(err)
	}
	lo0, lo1, hi0, hi1, err := e.RegReadYMM(3)
	if err != nil || lo0 != 1 || lo1 != 2 || hi0 != 3 || hi1 != 4 {
		t.Fatalf("got (%d,%d,%d,%d,%v)", lo0, lo1, hi0, hi1, err)
	}
}

func TestXMMVexZeroUpper(t *testing.T) {
	e := newSSEEngine(t)
	// Put something in ymmHi.
	e.regs.writeYMM(0, 1, 2, 0xAAAA, 0xBBBB)
	// VEX write should zero upper 128.
	e.regs.writeXMMVex(0, 10, 20)
	lo0, lo1, hi0, hi1 := e.regs.readYMM(0)
	if lo0 != 10 || lo1 != 20 || hi0 != 0 || hi1 != 0 {
		t.Fatalf("VEX zero-upper failed: (%d,%d,%d,%d)", lo0, lo1, hi0, hi1)
	}
}

func TestSSENoUpperZero(t *testing.T) {
	e := newSSEEngine(t)
	e.regs.writeYMM(0, 1, 2, 0xAAAA, 0xBBBB)
	// Non-VEX SSE write should NOT touch upper bits.
	e.regs.writeXMM(0, 10, 20)
	_, _, hi0, hi1 := e.regs.readYMM(0)
	if hi0 != 0xAAAA || hi1 != 0xBBBB {
		t.Fatalf("SSE should not zero upper: got (%x,%x)", hi0, hi1)
	}
}

func TestMXCSR(t *testing.T) {
	e := newSSEEngine(t)
	if err := e.RegWrite(RegMXCSR, 0x1F80); err != nil {
		t.Fatal(err)
	}
	v, err := e.RegRead(RegMXCSR)
	if err != nil || v != 0x1F80 {
		t.Fatalf("MXCSR: got %x, err %v", v, err)
	}
}

// ── Low-level lane helper tests (no instruction assembly needed) ──────────

func TestLane8(t *testing.T) {
	lo, hi := lane8(0x0102030405060708, 0x090a0b0c0d0e0f10,
		0x0101010101010101, 0x0101010101010101,
		func(a, b uint8) uint8 { return a + b })
	if lo != 0x0203040506070809 {
		t.Errorf("lo = %016x, want 0203040506070809", lo)
	}
	_ = hi
}

func TestLane32f(t *testing.T) {
	alo := uint64(math.Float32bits(1.0)) | uint64(math.Float32bits(2.0))<<32
	ahi := uint64(math.Float32bits(3.0)) | uint64(math.Float32bits(4.0))<<32
	blo := uint64(math.Float32bits(10.0)) | uint64(math.Float32bits(20.0))<<32
	bhi := uint64(math.Float32bits(30.0)) | uint64(math.Float32bits(40.0))<<32

	rlo, rhi := lane32f(alo, ahi, blo, bhi, func(a, b float32) float32 { return a + b })
	got := [4]float32{
		math.Float32frombits(uint32(rlo)),
		math.Float32frombits(uint32(rlo >> 32)),
		math.Float32frombits(uint32(rhi)),
		math.Float32frombits(uint32(rhi >> 32)),
	}
	want := [4]float32{11, 22, 33, 44}
	if got != want {
		t.Errorf("got %v, want %v", got, want)
	}
}

// ── Packed integer unit tests ─────────────────────────────────────────────

func TestPaddb(t *testing.T) {
	e := &Engine{}
	lo, _ := e.ssePaddb(0x0102030405060708, 0,
		0x0808080808080808, 0)
	if lo != 0x090a0b0c0d0e0f10 {
		t.Errorf("lo=%016x, want 090a0b0c0d0e0f10", lo)
	}
}

func TestPaddusb(t *testing.T) {
	e := &Engine{}
	// 0xFF + 0x01 should saturate to 0xFF.
	lo, _ := e.ssePaddusb(0xFF, 0, 0x01, 0)
	if lo != 0xFF {
		t.Errorf("got %x, want ff", lo)
	}
}

func TestPsubusb(t *testing.T) {
	e := &Engine{}
	// 0x01 - 0x02 should underflow to 0.
	lo, _ := e.ssePsubusb(0x01, 0, 0x02, 0)
	if lo != 0 {
		t.Errorf("got %x, want 0", lo)
	}
}

func TestPmullw(t *testing.T) {
	e := &Engine{}
	// 2 * 3 = 6 in lane 0.
	lo, _ := e.ssePmullw(0x0002, 0, 0x0003, 0)
	if uint16(lo) != 6 {
		t.Errorf("got %x, want 6", lo)
	}
}

func TestPcmpeqd(t *testing.T) {
	e := &Engine{}
	// Lane 0: 5 == 5 → all-ones. Lane 1: 5 != 6 → 0.
	lo, _ := e.ssePcmpeqd(
		uint64(5)|uint64(5)<<32, 0,
		uint64(5)|uint64(6)<<32, 0)
	if uint32(lo) != 0xFFFFFFFF {
		t.Errorf("lane0=%x, want ffffffff", uint32(lo))
	}
	if uint32(lo>>32) != 0 {
		t.Errorf("lane1=%x, want 0", uint32(lo>>32))
	}
}

func TestPcmpgtb(t *testing.T) {
	e := &Engine{}
	// int8(5) > int8(-1)?  Yes → 0xFF in lane 0.
	lo, _ := e.ssePcmpgtb(0x05, 0, 0xFF, 0) // 0xFF = int8(-1)
	if uint8(lo) != 0xFF {
		t.Errorf("got %x, want ff", uint8(lo))
	}
}

func TestPsrldq(t *testing.T) {
	lo, hi := ssePsrldq(0xDEADBEEFCAFEBABE, 0x0102030405060708, 8)
	if lo != 0x0102030405060708 {
		t.Errorf("lo=%016x", lo)
	}
	if hi != 0 {
		t.Errorf("hi=%016x", hi)
	}
}

func TestPslldq(t *testing.T) {
	lo, hi := ssePslldq(0xDEADBEEFCAFEBABE, 0x0102030405060708, 8)
	if hi != 0xDEADBEEFCAFEBABE {
		t.Errorf("hi=%016x", hi)
	}
	if lo != 0 {
		t.Errorf("lo=%016x", lo)
	}
}

func TestPunpcklbw(t *testing.T) {
	dlo := uint64(0x0102030405060708)
	slo := uint64(0xA1A2A3A4A5A6A7A8)
	lo, _ := ssePunpcklbw(dlo, 0, slo, 0)
	// In LE, byte 0 of dlo = 0x08, byte 0 of slo = 0xA8.
	if uint8(lo) != 0x08 {
		t.Errorf("result byte0=%02x, want 08", uint8(lo))
	}
	if uint8(lo>>8) != 0xA8 {
		t.Errorf("result byte1=%02x, want A8", uint8(lo>>8))
	}
}

func TestPshufd(t *testing.T) {
	// Load [1, 2, 3, 4] and shuffle with imm=0x4E: 01 00 11 10
	// => dst[0]=src[2], dst[1]=src[3], dst[2]=src[0], dst[3]=src[1]
	slo := uint64(1) | uint64(2)<<32
	shi := uint64(3) | uint64(4)<<32
	rlo, rhi := ssePshufd(slo, shi, 0x4E)
	if uint32(rlo) != 3 {
		t.Errorf("dst[0]=%d, want 3", uint32(rlo))
	}
	if uint32(rlo>>32) != 4 {
		t.Errorf("dst[1]=%d, want 4", uint32(rlo>>32))
	}
	if uint32(rhi) != 1 {
		t.Errorf("dst[2]=%d, want 1", uint32(rhi))
	}
	if uint32(rhi>>32) != 2 {
		t.Errorf("dst[3]=%d, want 2", uint32(rhi>>32))
	}
}

func TestPacksswb(t *testing.T) {
	// 200 (> 127) should saturate to 127.
	dlo := uint64(200) // int16(200) in lane 0
	lo, _ := ssePacksswb(dlo, 0, 0, 0)
	if int8(lo) != 127 {
		t.Errorf("saturate up: got %d, want 127", int8(lo))
	}
}

func TestPalignr(t *testing.T) {
	slo, shi := uint64(0x0102030405060708), uint64(0x090a0b0c0d0e0f10)
	dlo, dhi := uint64(0x1112131415161718), uint64(0x191a1b1c1d1e1f20)
	rlo, rhi := ssePalignr(dlo, dhi, slo, shi, 8)
	if rlo != shi {
		t.Errorf("rlo=%016x, want %016x", rlo, shi)
	}
	if rhi != dlo {
		t.Errorf("rhi=%016x, want %016x", rhi, dlo)
	}
}

// ── Packed float helper tests ─────────────────────────────────────────────

func TestAddps(t *testing.T) {
	e := &Engine{}
	alo := uint64(math.Float32bits(1)) | uint64(math.Float32bits(2))<<32
	ahi := uint64(math.Float32bits(3)) | uint64(math.Float32bits(4))<<32
	blo := uint64(math.Float32bits(10)) | uint64(math.Float32bits(20))<<32
	bhi := uint64(math.Float32bits(30)) | uint64(math.Float32bits(40))<<32
	rlo, rhi := e.sseAddps(alo, ahi, blo, bhi)
	want := [4]float32{11, 22, 33, 44}
	got := [4]float32{
		math.Float32frombits(uint32(rlo)),
		math.Float32frombits(uint32(rlo >> 32)),
		math.Float32frombits(uint32(rhi)),
		math.Float32frombits(uint32(rhi >> 32)),
	}
	if got != want {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestAddsd(t *testing.T) {
	rlo, rhi := sseAddsd(math.Float64bits(1.5), math.Float64bits(999), math.Float64bits(2.5), 0)
	if math.Float64frombits(rlo) != 4.0 {
		t.Errorf("got %v, want 4.0", math.Float64frombits(rlo))
	}
	if rhi != math.Float64bits(999) {
		t.Errorf("hi not preserved: got %x", rhi)
	}
}

func TestCmpss(t *testing.T) {
	// LT predicate (imm=1): 1.0 < 2.0 → all-ones mask.
	dlo := uint64(math.Float32bits(1.0))
	slo := uint64(math.Float32bits(2.0))
	rlo, _ := sseCmpss(dlo, 0, slo, 0, 1)
	if uint32(rlo) != 0xFFFFFFFF {
		t.Errorf("LT: got %08x, want ffffffff", uint32(rlo))
	}
	// NLT (imm=5): 1.0 is not >= 2.0 → false → 0.
	rlo, _ = sseCmpss(dlo, 0, slo, 0, 5)
	if uint32(rlo) != 0 {
		t.Errorf("NLT: got %08x, want 0", uint32(rlo))
	}
}

func TestComiss(t *testing.T) {
	e := &Engine{}
	e.regs.rflags = 0
	// 1.0 < 2.0 → CF=1, ZF=0.
	e.sseComiss(uint64(math.Float32bits(1.0)), uint64(math.Float32bits(2.0)))
	if !e.flag(flagCF) {
		t.Error("CF should be set for 1.0 < 2.0")
	}
	if e.flag(flagZF) {
		t.Error("ZF should be clear for 1.0 < 2.0")
	}
}

func TestComisd(t *testing.T) {
	e := &Engine{}
	e.regs.rflags = 0
	// 3.0 > 2.0 → CF=0, ZF=0.
	e.sseComisd(math.Float64bits(3.0), math.Float64bits(2.0))
	if e.flag(flagCF) {
		t.Error("CF should be clear for 3.0 > 2.0")
	}
	if e.flag(flagZF) {
		t.Error("ZF should be clear for 3.0 > 2.0")
	}
}

// ── Conversion helper tests ───────────────────────────────────────────────

func TestCvtsi2ss(t *testing.T) {
	rlo, _ := sseCvtsi2ss(0, 0, 42)
	if math.Float32frombits(uint32(rlo)) != 42.0 {
		t.Errorf("got %v, want 42.0", math.Float32frombits(uint32(rlo)))
	}
}

func TestCvtsi2sd(t *testing.T) {
	rlo, _ := sseCvtsi2sd(0, 0, -7)
	if math.Float64frombits(rlo) != -7.0 {
		t.Errorf("got %v, want -7.0", math.Float64frombits(rlo))
	}
}

func TestCvttss2si(t *testing.T) {
	slo := uint64(math.Float32bits(3.9))
	if sseCvttss2si(slo) != 3 {
		t.Errorf("got %d, want 3", sseCvttss2si(slo))
	}
}

func TestCvttsd2si(t *testing.T) {
	slo := math.Float64bits(-2.7)
	if sseCvttsd2si(slo) != -2 {
		t.Errorf("got %d, want -2", sseCvttsd2si(slo))
	}
}

func TestCvtdq2ps(t *testing.T) {
	slo := uint64(1) | uint64(2)<<32
	shi := uint64(3) | uint64(4)<<32
	rlo, rhi := sseCvtdq2ps(slo, shi)
	got := [4]float32{
		math.Float32frombits(uint32(rlo)),
		math.Float32frombits(uint32(rlo >> 32)),
		math.Float32frombits(uint32(rhi)),
		math.Float32frombits(uint32(rhi >> 32)),
	}
	if got != ([4]float32{1, 2, 3, 4}) {
		t.Errorf("got %v", got)
	}
}

func TestCvtps2pd(t *testing.T) {
	slo := uint64(math.Float32bits(1.5)) | uint64(math.Float32bits(2.5))<<32
	rlo, rhi := sseCvtps2pd(slo, 0)
	if math.Float64frombits(rlo) != 1.5 {
		t.Errorf("lo=%v", math.Float64frombits(rlo))
	}
	if math.Float64frombits(rhi) != 2.5 {
		t.Errorf("hi=%v", math.Float64frombits(rhi))
	}
}

// ── RoundXX tests ─────────────────────────────────────────────────────────

func TestRoundsd(t *testing.T) {
	cases := []struct {
		f    float64
		imm  uint8
		want float64
	}{
		{2.5, 0, 2.0},   // round-to-even
		{2.5, 1, 2.0},   // floor
		{2.5, 2, 3.0},   // ceil
		{2.5, 3, 2.0},   // truncate
		{-2.5, 1, -3.0}, // floor
	}
	for _, tc := range cases {
		rlo, _ := sseRoundsd(math.Float64bits(tc.f), 0, tc.imm)
		got := math.Float64frombits(rlo)
		if got != tc.want {
			t.Errorf("roundsd(%v, imm=%d) = %v, want %v", tc.f, tc.imm, got, tc.want)
		}
	}
}

// ── AVX helper tests ──────────────────────────────────────────────────────

func TestVbroadcastss(t *testing.T) {
	src := math.Float32bits(3.14)
	lo, hi, hi0, hi1 := sseVbroadcastss(src, true /* L=1 */)
	for i, v := range []uint64{lo, hi, hi0, hi1} {
		if uint32(v) != src || uint32(v>>32) != src {
			t.Errorf("lane%d=%016x, want %08x repeated", i, v, src)
		}
	}
}

func TestVperm2f128(t *testing.T) {
	dlo, dhi := uint64(10), uint64(11)
	d2lo, d2hi := uint64(12), uint64(13)
	slo, shi := uint64(20), uint64(21)
	s2lo, s2hi := uint64(22), uint64(23)
	// imm=0x31: lower result = index 1 (d2lo/d2hi), upper = index 3 (s2lo/s2hi).
	r0, r1, r2, r3 := sseVperm2f128(dlo, dhi, d2lo, d2hi, slo, shi, s2lo, s2hi, 0x31)
	if r0 != 12 || r1 != 13 {
		t.Errorf("lower=(%d,%d), want (12,13)", r0, r1)
	}
	if r2 != 22 || r3 != 23 {
		t.Errorf("upper=(%d,%d), want (22,23)", r2, r3)
	}
}

func TestVinsertf128(t *testing.T) {
	dlo, dhi := uint64(1), uint64(2)
	d2lo, d2hi := uint64(3), uint64(4)
	slo, shi := uint64(99), uint64(100)
	// imm=0: insert into lower half.
	r0, r1, r2, r3 := sseVinsertf128(dlo, dhi, d2lo, d2hi, slo, shi, 0)
	if r0 != 99 || r1 != 100 || r2 != 3 || r3 != 4 {
		t.Errorf("insertf128 imm=0: got (%d,%d,%d,%d)", r0, r1, r2, r3)
	}
	// imm=1: insert into upper half.
	r0, r1, r2, r3 = sseVinsertf128(dlo, dhi, d2lo, d2hi, slo, shi, 1)
	if r0 != 1 || r1 != 2 || r2 != 99 || r3 != 100 {
		t.Errorf("insertf128 imm=1: got (%d,%d,%d,%d)", r0, r1, r2, r3)
	}
}

// ── VEX decode tests ──────────────────────────────────────────────────────

func TestDecodeVEXPrefix2Byte(t *testing.T) {
	// C5 78: bit7=0 → R=true, vvvv=0, L=0, pp=0, map=1.
	e := newSSEEngine(t)
	if err := e.MemMap(0x1000, 0x1000, ProtRead|ProtExec); err != nil {
		t.Fatal(err)
	}
	b := []byte{0x78}
	if err := e.MemWrite(0x1000, b); err != nil {
		t.Fatal(err)
	}
	c := &cursor{e: e, base: 0x1000}
	vx, err := decodeVEXPrefix(c, 0xC5)
	if err != nil {
		t.Fatal(err)
	}
	if !vx.present {
		t.Error("present should be true")
	}
	if !vx.R {
		t.Error("R should be true (bit7 of 0x78 is 0 → R=true)")
	}
	if vx.L {
		t.Error("L should be false")
	}
	if vx.mapSelect != 1 {
		t.Errorf("mapSelect=%d, want 1", vx.mapSelect)
	}
}

func TestDecodeVEXPrefix3Byte(t *testing.T) {
	// C4 E1 79: b1=E1 → map=1; b2=79 → pp=1 (66).
	e := newSSEEngine(t)
	if err := e.MemMap(0x1000, 0x1000, ProtRead|ProtExec); err != nil {
		t.Fatal(err)
	}
	b := []byte{0xE1, 0x79}
	if err := e.MemWrite(0x1000, b); err != nil {
		t.Fatal(err)
	}
	c := &cursor{e: e, base: 0x1000}
	vx, err := decodeVEXPrefix(c, 0xC4)
	if err != nil {
		t.Fatal(err)
	}
	if vx.mapSelect != 1 {
		t.Errorf("mapSelect=%d, want 1", vx.mapSelect)
	}
	if vx.pp != 1 {
		t.Errorf("pp=%d, want 1 (66)", vx.pp)
	}
	if !vx.opSize16() {
		t.Error("opSize16() should be true for pp=1")
	}
}

// ── Ptest ─────────────────────────────────────────────────────────────────

func TestPtest(t *testing.T) {
	e := &Engine{}
	e.regs.rflags = 0
	// dst=0xFF, src=0x00: AND=0 → ZF=1; ANDN(~0xFF & 0x00)=0 → CF=1.
	e.ssePtest(0xFF, 0, 0x00, 0)
	if !e.flag(flagZF) {
		t.Error("ZF should be set")
	}
	if !e.flag(flagCF) {
		t.Error("CF should be set")
	}
}

// ── insertps ──────────────────────────────────────────────────────────────

func TestInsertps(t *testing.T) {
	// dest = [1.0, 2.0, 3.0, 4.0], insert 9.0 at dest position 2, zmask=0.
	// imm = (count_s=0 | count_d=2)<<4 | 0 = 0x20
	dlo := uint64(math.Float32bits(1.0)) | uint64(math.Float32bits(2.0))<<32
	dhi := uint64(math.Float32bits(3.0)) | uint64(math.Float32bits(4.0))<<32
	src := math.Float32bits(9.0)
	rlo, rhi := sseInsertps(dlo, dhi, src, 0x20)
	if math.Float32frombits(uint32(rlo)) != 1.0 {
		t.Errorf("lane0=%v", math.Float32frombits(uint32(rlo)))
	}
	if math.Float32frombits(uint32(rlo>>32)) != 2.0 {
		t.Errorf("lane1=%v", math.Float32frombits(uint32(rlo>>32)))
	}
	if math.Float32frombits(uint32(rhi)) != 9.0 {
		t.Errorf("lane2=%v", math.Float32frombits(uint32(rhi)))
	}
	if math.Float32frombits(uint32(rhi>>32)) != 4.0 {
		t.Errorf("lane3=%v", math.Float32frombits(uint32(rhi>>32)))
	}
}

// ── DPPS / DPPD ───────────────────────────────────────────────────────────

func TestDpps(t *testing.T) {
	// [1,2,3,4] · [1,1,1,1] = 10, all output lanes.
	dlo := uint64(math.Float32bits(1.0)) | uint64(math.Float32bits(2.0))<<32
	dhi := uint64(math.Float32bits(3.0)) | uint64(math.Float32bits(4.0))<<32
	slo := uint64(math.Float32bits(1.0)) | uint64(math.Float32bits(1.0))<<32
	shi := uint64(math.Float32bits(1.0)) | uint64(math.Float32bits(1.0))<<32
	rlo, rhi := sseDpps(dlo, dhi, slo, shi, 0xFF)
	for i, v := range []uint64{rlo & 0xFFFFFFFF, rlo >> 32, rhi & 0xFFFFFFFF, rhi >> 32} {
		if math.Float32frombits(uint32(v)) != 10.0 {
			t.Errorf("lane%d=%v, want 10.0", i, math.Float32frombits(uint32(v)))
		}
	}
}

func TestDppd(t *testing.T) {
	// [1.0, 2.0] · [3.0, 4.0] = 11.0 in both output lanes.
	dlo := math.Float64bits(1.0)
	dhi := math.Float64bits(2.0)
	slo := math.Float64bits(3.0)
	shi := math.Float64bits(4.0)
	rlo, rhi := sseDppd(dlo, dhi, slo, shi, 0x33)
	if math.Float64frombits(rlo) != 11.0 {
		t.Errorf("lane0=%v, want 11.0", math.Float64frombits(rlo))
	}
	if math.Float64frombits(rhi) != 11.0 {
		t.Errorf("lane1=%v, want 11.0", math.Float64frombits(rhi))
	}
}

// ── HADDPS / HADDPD ───────────────────────────────────────────────────────

func TestHaddps(t *testing.T) {
	// dst=[1,2,3,4], src=[10,20,30,40] → [3,7,30,70]
	dlo := uint64(math.Float32bits(1)) | uint64(math.Float32bits(2))<<32
	dhi := uint64(math.Float32bits(3)) | uint64(math.Float32bits(4))<<32
	slo := uint64(math.Float32bits(10)) | uint64(math.Float32bits(20))<<32
	shi := uint64(math.Float32bits(30)) | uint64(math.Float32bits(40))<<32
	rlo, rhi := sseHaddps(dlo, dhi, slo, shi)
	got := [4]float32{
		math.Float32frombits(uint32(rlo)),
		math.Float32frombits(uint32(rlo >> 32)),
		math.Float32frombits(uint32(rhi)),
		math.Float32frombits(uint32(rhi >> 32)),
	}
	want := [4]float32{3, 7, 30, 70}
	if got != want {
		t.Errorf("got %v, want %v", got, want)
	}
}

// ── Movmsk tests ──────────────────────────────────────────────────────────

func TestMovmskps(t *testing.T) {
	lo := uint64(math.Float32bits(-1.0)) | uint64(math.Float32bits(1.0))<<32
	hi := uint64(math.Float32bits(1.0)) | uint64(math.Float32bits(-1.0))<<32
	mask := sseMovmskps(lo, hi)
	if mask != 0b1001 {
		t.Errorf("mask=%04b, want 1001", mask)
	}
}

func TestMovmskpd(t *testing.T) {
	lo := math.Float64bits(-1.0)
	hi := math.Float64bits(1.0)
	mask := sseMovmskpd(lo, hi)
	if mask != 0b01 {
		t.Errorf("mask=%02b, want 01", mask)
	}
}

// ── PSADBW ────────────────────────────────────────────────────────────────

func TestPsadbw(t *testing.T) {
	e := &Engine{}
	// |1-2|*8 = 8 in the low word.
	dlo := uint64(0x0101010101010101)
	slo := uint64(0x0202020202020202)
	lo, hi := e.ssePsadbw(dlo, 0, slo, 0)
	if lo != 8 {
		t.Errorf("lo=%d, want 8", lo)
	}
	if hi != 0 {
		t.Errorf("hi=%d, want 0", hi)
	}
}

// ── PMOVMSKB ──────────────────────────────────────────────────────────────

func TestPmovmskb(t *testing.T) {
	// byte 0 = 0x80 (sign set), byte 15 = 0x80 (sign set), rest 0.
	lo := uint64(0x80)
	hi := uint64(0x80) << 56
	mask := ssePmovmskb(lo, hi)
	if mask&1 == 0 {
		t.Error("bit0 should be set")
	}
	if mask>>15&1 == 0 {
		t.Error("bit15 should be set")
	}
	if mask&^uint32(0x8001) != 0 {
		t.Errorf("unexpected bits: %016b", mask)
	}
}
