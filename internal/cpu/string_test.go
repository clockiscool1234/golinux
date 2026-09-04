package cpu

import "testing"

func TestRepStosq(t *testing.T) {
	code := assemble(t, `
		mov $0x600000, %rdi
		mov $10, %rcx
		mov $0x4141414141414141, %rax
		cld
		rep stos %rax, %es:(%rdi)
	`)
	e := newTestEngine(t, code)
	if err := e.MemMap(0x600000, pageSize, ProtRead|ProtWrite); err != nil {
		t.Fatal(err)
	}
	end := testCodeBase + uint64(len(code))
	if err := e.EmuStart(testCodeBase, end); err != nil {
		t.Fatalf("EmuStart: %v", err)
	}
	if got, want := reg(t, e, RegRCX), uint64(0); got != want {
		t.Fatalf("rcx = %d, want %d (REP should have exhausted the counter)", got, want)
	}
	if got, want := reg(t, e, RegRDI), uint64(0x600000+10*8); got != want {
		t.Fatalf("rdi = %#x, want %#x", got, want)
	}
	buf, err := e.MemRead(0x600000, 80)
	if err != nil {
		t.Fatal(err)
	}
	for i, b := range buf {
		if b != 0x41 {
			t.Fatalf("byte %d = %#x, want 0x41", i, b)
		}
	}
}

func TestRepMovsb(t *testing.T) {
	code := assemble(t, `
		mov $0x600000, %rsi
		mov $0x601000, %rdi
		mov $5, %rcx
		cld
		rep movsb
	`)
	e := newTestEngine(t, code)
	if err := e.MemMap(0x600000, pageSize, ProtRead|ProtWrite); err != nil {
		t.Fatal(err)
	}
	if err := e.MemMap(0x601000, pageSize, ProtRead|ProtWrite); err != nil {
		t.Fatal(err)
	}
	if err := e.MemWrite(0x600000, []byte("hello world")); err != nil {
		t.Fatal(err)
	}
	end := testCodeBase + uint64(len(code))
	if err := e.EmuStart(testCodeBase, end); err != nil {
		t.Fatalf("EmuStart: %v", err)
	}
	got, err := e.MemRead(0x601000, 5)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Fatalf("copied %q, want %q", got, "hello")
	}
	if rsi, want := reg(t, e, RegRSI), uint64(0x600005); rsi != want {
		t.Fatalf("rsi = %#x, want %#x", rsi, want)
	}
}

func TestRepeCmpsbStopsOnMismatch(t *testing.T) {
	code := assemble(t, `
		mov $0x600000, %rsi
		mov $0x601000, %rdi
		mov $10, %rcx
		cld
		repe cmpsb
	`)
	e := newTestEngine(t, code)
	if err := e.MemMap(0x600000, pageSize, ProtRead|ProtWrite); err != nil {
		t.Fatal(err)
	}
	if err := e.MemMap(0x601000, pageSize, ProtRead|ProtWrite); err != nil {
		t.Fatal(err)
	}
	if err := e.MemWrite(0x600000, []byte("abcXefghij")); err != nil {
		t.Fatal(err)
	}
	if err := e.MemWrite(0x601000, []byte("abcYefghij")); err != nil {
		t.Fatal(err)
	}
	end := testCodeBase + uint64(len(code))
	if err := e.EmuStart(testCodeBase, end); err != nil {
		t.Fatalf("EmuStart: %v", err)
	}
	// Should stop right after comparing the 4th byte ('X' vs 'Y'),
	// having consumed 4 of the 10 iterations.
	if got, want := reg(t, e, RegRCX), uint64(6); got != want {
		t.Fatalf("rcx = %d, want %d", got, want)
	}
	if e.flag(flagZF) {
		t.Fatalf("ZF should be clear (bytes differed)")
	}
}

func TestStdReversesDirection(t *testing.T) {
	code := assemble(t, `
		mov $0x600010, %rdi
		mov $4, %rcx
		mov $0x42, %al
		std
		rep stosb
	`)
	e := newTestEngine(t, code)
	if err := e.MemMap(0x600000, pageSize, ProtRead|ProtWrite); err != nil {
		t.Fatal(err)
	}
	end := testCodeBase + uint64(len(code))
	if err := e.EmuStart(testCodeBase, end); err != nil {
		t.Fatalf("EmuStart: %v", err)
	}
	// STD + STOSB should walk backwards: 0x600010, 0x60000f, 0x60000e, 0x60000d.
	if got, want := reg(t, e, RegRDI), uint64(0x60000c); got != want {
		t.Fatalf("rdi = %#x, want %#x", got, want)
	}
	got, err := e.MemRead(0x60000d, 4)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range got {
		if b != 0x42 {
			t.Fatalf("bytes = % x, want all 0x42", got)
		}
	}
}
