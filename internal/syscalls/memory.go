package syscalls

import (
	"golinux/internal/consts"
	"golinux/internal/errno"
)

func init() {
	register(consts.SYS_brk, sysBrk)
	register(consts.SYS_mmap, sysMmap)
	register(consts.SYS_munmap, sysMunmap)
	register(consts.SYS_mprotect, sysMprotect)
}

func sysBrk(proc Proc, addr, _, _, _, _, _ uint64) (int64, error) {
	return int64(proc.DoBrk(addr)), nil
}

func sysMmap(proc Proc, addr, length, prot, flags, fdNum, offset uint64) (int64, error) {
	base, err := proc.DoMmap(addr, length, int(prot), int(flags), int(int32(fdNum)), offset)
	if err != nil {
		return int64(-errno.ENOMEM), nil
	}
	return int64(base), nil
}

func sysMunmap(proc Proc, addr, length, _, _, _, _ uint64) (int64, error) {
	_ = proc.DoMunmap(addr, length)
	return 0, nil
}

func sysMprotect(proc Proc, addr, length, prot, _, _, _ uint64) (int64, error) {
	_ = proc.DoMprotect(addr, length, int(prot))
	return 0, nil
}
