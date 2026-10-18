package cpu

import "testing"

func TestBlockJITStopsAtUntilInsideBlock(t *testing.T) {
	code := []byte{0xb8, 1, 0, 0, 0, 0xbb, 2, 0, 0, 0, 0x90}
	for _, enabled := range []bool{false, true} {
		e := newTestEngine(t, code)
		e.SetBlockJIT(enabled)
		if err := e.EmuStart(testCodeBase, testCodeBase+5); err != nil {
			t.Fatalf("EmuStart(jit=%v): %v", enabled, err)
		}
		if got := reg(t, e, RegRAX); got != 1 {
			t.Fatalf("jit=%v: RAX = %d; want 1", enabled, got)
		}
		if got := reg(t, e, RegRBX); got != 0 {
			t.Fatalf("jit=%v executed past until: RBX = %d; want 0", enabled, got)
		}
	}
}
