package elfload

import (
	"os"
	"testing"
)

func TestParseMuslStaticHello(t *testing.T) {
	path := "/tmp/hello_musl"
	if _, err := os.Stat(path); err != nil {
		t.Skip("no compiled test binary at", path)
	}
	img, err := ParseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if img.Type != ET_EXEC {
		t.Fatalf("expected ET_EXEC (static, no-pie), got %d", img.Type)
	}
	if img.Interp != "" {
		t.Fatalf("expected no PT_INTERP for a static binary, got %q", img.Interp)
	}
	if img.Entry == 0 {
		t.Fatal("expected non-zero entry point")
	}
	segs, err := LoadSegments(img)
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) == 0 {
		t.Fatal("expected at least one PT_LOAD segment")
	}
	for _, s := range segs {
		if len(s.Data) != int(s.Memsz) {
			t.Fatalf("segment data len %d != memsz %d", len(s.Data), s.Memsz)
		}
	}
}

func TestParseGlibcDynamicBinary(t *testing.T) {
	// /bin/ls on the host is virtually always a dynamically linked ELF64.
	path := "/bin/ls"
	if _, err := os.Stat(path); err != nil {
		t.Skip("no /bin/ls to test against")
	}
	img, err := ParseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if img.Interp == "" {
		t.Fatal("expected a PT_INTERP dynamic linker path")
	}
	t.Logf("interp = %s, type = %d, entry = %#x", img.Interp, img.Type, img.Entry)
}

func TestRejectsNonELF(t *testing.T) {
	_, err := ParseBytes([]byte("not an elf file at all"), "junk")
	if err == nil {
		t.Fatal("expected error for non-ELF data")
	}
}
