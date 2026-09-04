package syscalls

import (
	"encoding/binary"

	"golinux/internal/consts"
	"golinux/internal/errno"
)

func init() {
	register(consts.SYS_arch_prctl, sysArchPrctl)
	register(consts.SYS_set_tid_address, sysSetTidAddress)
	register(consts.SYS_set_robust_list, sysSetRobustList)
	register(consts.SYS_rseq, sysRseq)
}

const (
	archSetGS = 0x1001
	archSetFS = 0x1002
	archGetFS = 0x1003
	archGetGS = 0x1004
)

func sysArchPrctl(proc Proc, code, addr, _, _, _, _ uint64) (int64, error) {
	switch code {
	case archSetFS:
		proc.SetFSBase(addr)
		return 0, nil
	case archGetFS:
		buf := make([]byte, 8)
		binary.LittleEndian.PutUint64(buf, proc.GetFSBase())
		if err := proc.MemWrite(addr, buf); err != nil {
			return int64(-errno.EFAULT), nil
		}
		return 0, nil
	}
	return 0, nil
}

func sysSetTidAddress(proc Proc, _, _, _, _, _, _ uint64) (int64, error) {
	return int64(proc.Pid()), nil
}

// sysSetRobustList/sysRseq are glibc startup bookkeeping this
// emulator has no use for (robust futex lists and restartable
// sequences both only matter across real preemption, which a
// single-threaded guest never experiences here). Reporting success
// keeps glibc's startup path happy instead of it falling back to
// slower alternatives after seeing ENOSYS.
func sysSetRobustList(proc Proc, _, _, _, _, _, _ uint64) (int64, error) {
	return 0, nil
}

func sysRseq(proc Proc, _, _, _, _, _, _ uint64) (int64, error) {
	return 0, nil
}
