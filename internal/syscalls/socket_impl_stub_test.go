//go:build !linux

package syscalls

import (
	"testing"

	"golinux/internal/errno"
)

func TestSocketSyscallsReturnENOSYSOutsideLinux(t *testing.T) {
	got, err := sysSocket(nil, 0, 0, 0, 0, 0, 0)
	if err != nil {
		t.Fatalf("sysSocket error = %v; want nil", err)
	}
	if got != int64(-errno.ENOSYS) {
		t.Fatalf("sysSocket = %d; want -ENOSYS", got)
	}
}
