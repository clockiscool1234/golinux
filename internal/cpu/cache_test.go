package cpu

import "testing"

func TestExecutableWriteInvalidatesDecodedPage(t *testing.T) {
	code := assemble(t, "mov $1, %eax")
	e := newTestEngine(t, code)
	end := testCodeBase + uint64(len(code))

	if err := e.EmuStart(testCodeBase, end); err != nil {
		t.Fatal(err)
	}
	if got := reg(t, e, RegRAX); got != 1 {
		t.Fatalf("first execution rax = %d, want 1", got)
	}

	if err := e.MemWrite(testCodeBase, []byte{0xb8, 2, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	if err := e.EmuStart(testCodeBase, end); err != nil {
		t.Fatal(err)
	}
	if got := reg(t, e, RegRAX); got != 2 {
		t.Fatalf("after code write rax = %d, want 2", got)
	}
}
