package devices

import (
	"bytes"
	"testing"

	"golinux/internal/fds"
)

type stubProc struct{ t *fds.Table }

func (s *stubProc) Fds() *fds.Table { return s.t }

func TestNullDevice(t *testing.T) {
	dev, ok := Open("/dev/null", (1<<8)|3, &stubProc{fds.NewTable()})
	if !ok {
		t.Fatal("expected /dev/null (1,3) to be recognized")
	}
	n, err := dev.Write([]byte("discarded"))
	if err != nil || n != 9 {
		t.Fatalf("write to /dev/null: n=%d err=%v", n, err)
	}
	data, err := dev.Read(16)
	if err != nil || len(data) != 0 {
		t.Fatalf("read from /dev/null should be empty: %v %v", data, err)
	}
}

func TestZeroDevice(t *testing.T) {
	dev, ok := Open("/dev/zero", (1<<8)|5, &stubProc{fds.NewTable()})
	if !ok {
		t.Fatal("expected /dev/zero (1,5) to be recognized")
	}
	data, err := dev.Read(16)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, make([]byte, 16)) {
		t.Fatalf("expected 16 zero bytes, got %v", data)
	}
}

func TestFullDevice(t *testing.T) {
	dev, ok := Open("/dev/full", (1<<8)|7, &stubProc{fds.NewTable()})
	if !ok {
		t.Fatal("expected /dev/full (1,7) to be recognized")
	}
	_, err := dev.Write([]byte("x"))
	if err == nil {
		t.Fatal("expected /dev/full write to fail")
	}
	ee, ok := err.(*fds.ErrnoError)
	if !ok || ee.Errno != 28 { // ENOSPC
		t.Fatalf("expected ENOSPC, got %v", err)
	}
}

func TestUnknownDevice(t *testing.T) {
	_, ok := Open("/dev/weird", (99<<8)|99, &stubProc{fds.NewTable()})
	if ok {
		t.Fatal("expected an unmodeled (major,minor) to be rejected")
	}
}
