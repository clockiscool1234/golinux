package cpu

import (
	"encoding/binary"
	"math"
	"testing"
)

func TestX87LoadDoubleStoreExtended(t *testing.T) {
	code := []byte{0xdd, 0x03, 0xdb, 0x39}
	e := newTestEngine(t, code)
	inputAddr, outputAddr := uint64(0x500000), uint64(0x501000)
	if err := e.MemMap(inputAddr, pageSize, ProtRead|ProtWrite); err != nil {
		t.Fatal(err)
	}
	if err := e.MemMap(outputAddr, pageSize, ProtRead|ProtWrite); err != nil {
		t.Fatal(err)
	}
	input := make([]byte, 8)
	binary.LittleEndian.PutUint64(input, math.Float64bits(-1.5))
	if err := e.MemWrite(inputAddr, input); err != nil {
		t.Fatal(err)
	}
	if err := e.RegWrite(RegRBX, inputAddr); err != nil {
		t.Fatal(err)
	}
	if err := e.RegWrite(RegRCX, outputAddr); err != nil {
		t.Fatal(err)
	}
	if err := e.EmuStart(testCodeBase, testCodeBase+uint64(len(code))); err != nil {
		t.Fatal(err)
	}
	got, err := e.MemRead(outputAddr, 10)
	if err != nil {
		t.Fatal(err)
	}
	if significand := binary.LittleEndian.Uint64(got[:8]); significand != 0xc000000000000000 {
		t.Fatalf("extended significand = %#x; want %#x", significand, uint64(0xc000000000000000))
	}
	if signExponent := binary.LittleEndian.Uint16(got[8:]); signExponent != 0xbfff {
		t.Fatalf("extended sign/exponent = %#x; want %#x", signExponent, uint16(0xbfff))
	}
	if e.regs.x87Top != 0 {
		t.Fatalf("x87 stack top after FSTP = %d; want 0", e.regs.x87Top)
	}
}

func TestX87LoadRegisterAndStore(t *testing.T) {
	code := []byte{0xdd, 0x03, 0xd9, 0xc0, 0xdb, 0x39}
	e := newTestEngine(t, code)
	inputAddr, outputAddr := uint64(0x500000), uint64(0x501000)
	if err := e.MemMap(inputAddr, pageSize, ProtRead|ProtWrite); err != nil {
		t.Fatal(err)
	}
	if err := e.MemMap(outputAddr, pageSize, ProtRead|ProtWrite); err != nil {
		t.Fatal(err)
	}
	input := make([]byte, 8)
	binary.LittleEndian.PutUint64(input, math.Float64bits(1.5))
	if err := e.MemWrite(inputAddr, input); err != nil {
		t.Fatal(err)
	}
	if err := e.RegWrite(RegRBX, inputAddr); err != nil {
		t.Fatal(err)
	}
	if err := e.RegWrite(RegRCX, outputAddr); err != nil {
		t.Fatal(err)
	}
	if err := e.EmuStart(testCodeBase, testCodeBase+uint64(len(code))); err != nil {
		t.Fatal(err)
	}
	got, err := e.MemRead(outputAddr, 10)
	if err != nil {
		t.Fatal(err)
	}
	if significand := binary.LittleEndian.Uint64(got[:8]); significand != 0xc000000000000000 {
		t.Fatalf("extended significand = %#x; want %#x", significand, uint64(0xc000000000000000))
	}
	if signExponent := binary.LittleEndian.Uint16(got[8:]); signExponent != 0x3fff {
		t.Fatalf("extended sign/exponent = %#x; want %#x", signExponent, uint16(0x3fff))
	}
	if e.regs.x87Top != 7 {
		t.Fatalf("x87 stack top after FLD ST(0) and FSTP = %d; want 7", e.regs.x87Top)
	}
}

func TestX87MuslLongDoubleFormattingSequence(t *testing.T) {
	code := []byte{0xdb, 0x2b, 0xd9, 0xc0, 0xd8, 0xc0, 0xd9, 0xee, 0xd9, 0xc9, 0xdf, 0xe9, 0xdd, 0xd8}
	e := newTestEngine(t, code)
	inputAddr := uint64(0x500000)
	if err := e.MemMap(inputAddr, pageSize, ProtRead|ProtWrite); err != nil {
		t.Fatal(err)
	}
	input := make([]byte, 10)
	binary.LittleEndian.PutUint64(input[:8], 0xc000000000000000)
	binary.LittleEndian.PutUint16(input[8:], 0x3fff)
	if err := e.MemWrite(inputAddr, input); err != nil {
		t.Fatal(err)
	}
	if err := e.RegWrite(RegRBX, inputAddr); err != nil {
		t.Fatal(err)
	}
	if err := e.EmuStart(testCodeBase, testCodeBase+uint64(len(code))); err != nil {
		t.Fatal(err)
	}
	if e.regs.x87Top != 7 || e.regs.x87[7] != (ext80{significand: 0xc000000000000000, signExponent: 0x3fff}) {
		t.Fatalf("x87 state after musl sequence = top %d, ST0 %#v", e.regs.x87Top, e.regs.x87[e.regs.x87Top])
	}
	if e.flag(flagCF) || e.flag(flagPF) || e.flag(flagZF) {
		t.Fatalf("FUCOMIP flags for 3.0 > 0.0: CF=%t PF=%t ZF=%t", e.flag(flagCF), e.flag(flagPF), e.flag(flagZF))
	}
}

func TestX87LoadAndStoreExtendedPrecision(t *testing.T) {
	code := []byte{0xdb, 0x2b, 0xd9, 0xc0, 0xdb, 0x39, 0xdd, 0xd8}
	e := newTestEngine(t, code)
	inputAddr, outputAddr := uint64(0x500000), uint64(0x501000)
	if err := e.MemMap(inputAddr, pageSize, ProtRead|ProtWrite); err != nil {
		t.Fatal(err)
	}
	if err := e.MemMap(outputAddr, pageSize, ProtRead|ProtWrite); err != nil {
		t.Fatal(err)
	}
	input := make([]byte, 10)
	binary.LittleEndian.PutUint64(input[:8], 0xc000000000000000)
	binary.LittleEndian.PutUint16(input[8:], 0x3fff)
	if err := e.MemWrite(inputAddr, input); err != nil {
		t.Fatal(err)
	}
	if err := e.RegWrite(RegRBX, inputAddr); err != nil {
		t.Fatal(err)
	}
	if err := e.RegWrite(RegRCX, outputAddr); err != nil {
		t.Fatal(err)
	}
	if err := e.EmuStart(testCodeBase, testCodeBase+uint64(len(code))); err != nil {
		t.Fatal(err)
	}
	got, err := e.MemRead(outputAddr, 10)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(input) {
		t.Fatalf("extended value = % x; want % x", got, input)
	}
	if e.regs.x87Top != 0 {
		t.Fatalf("x87 stack top after FSTP ST(0) = %d; want 0", e.regs.x87Top)
	}
}
