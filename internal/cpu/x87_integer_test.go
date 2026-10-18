package cpu

import (
	"encoding/binary"
	"testing"
)

func TestX87FistpM64RoundsNearestEven(t *testing.T) {
	code := []byte{0xdb, 0x2b, 0xdf, 0x39}
	e := newTestEngine(t, code)
	inputAddr, outputAddr := uint64(0x500000), uint64(0x501000)
	if err := e.MemMap(inputAddr, pageSize, ProtRead|ProtWrite); err != nil {
		t.Fatal(err)
	}
	if err := e.MemMap(outputAddr, pageSize, ProtRead|ProtWrite); err != nil {
		t.Fatal(err)
	}
	input := make([]byte, 10)
	binary.LittleEndian.PutUint64(input[:8], 0xa000000000000000)
	binary.LittleEndian.PutUint16(input[8:], 0x4000)
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
	got, err := e.MemRead(outputAddr, 8)
	if err != nil {
		t.Fatal(err)
	}
	if integer := binary.LittleEndian.Uint64(got); integer != 2 {
		t.Fatalf("FISTP rounded 2.5 to %d; want nearest-even 2", int64(integer))
	}
	if e.regs.x87Top != 0 {
		t.Fatalf("x87 stack top after FISTP = %d; want 0", e.regs.x87Top)
	}
}

func TestX87FistpM64TruncatesWhenControlWordRequestsIt(t *testing.T) {
	code := []byte{0xdb, 0x2b, 0xdf, 0x39}
	e := newTestEngine(t, code)
	e.regs.x87Control = (e.regs.x87Control &^ 0x0c00) | 0x0c00
	inputAddr, outputAddr := uint64(0x500000), uint64(0x501000)
	if err := e.MemMap(inputAddr, pageSize, ProtRead|ProtWrite); err != nil {
		t.Fatal(err)
	}
	if err := e.MemMap(outputAddr, pageSize, ProtRead|ProtWrite); err != nil {
		t.Fatal(err)
	}
	input := make([]byte, 10)
	binary.LittleEndian.PutUint64(input[:8], 0xa000000000000000)
	binary.LittleEndian.PutUint16(input[8:], 0xc000)
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
	got, err := e.MemRead(outputAddr, 8)
	if err != nil {
		t.Fatal(err)
	}
	if integer := int64(binary.LittleEndian.Uint64(got)); integer != -2 {
		t.Fatalf("FISTP truncated -2.5 to %d; want -2", integer)
	}
}
