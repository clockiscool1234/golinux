package cpu

import (
	"encoding/binary"
	"testing"
)

func TestX87FildAndFsubp(t *testing.T) {
	code := []byte{0xdf, 0x2b, 0xd9, 0xee, 0xd9, 0xc9, 0xde, 0xe9, 0xdb, 0x39}
	e := newTestEngine(t, code)
	inputAddr, outputAddr := uint64(0x500000), uint64(0x501000)
	if err := e.MemMap(inputAddr, pageSize, ProtRead|ProtWrite); err != nil {
		t.Fatal(err)
	}
	if err := e.MemMap(outputAddr, pageSize, ProtRead|ProtWrite); err != nil {
		t.Fatal(err)
	}
	input := make([]byte, 8)
	binary.LittleEndian.PutUint64(input, 3)
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
	if signExponent := binary.LittleEndian.Uint16(got[8:]); signExponent != 0xc000 {
		t.Fatalf("extended sign/exponent = %#x; want %#x", signExponent, uint16(0xc000))
	}
}
