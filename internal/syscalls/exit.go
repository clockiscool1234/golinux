package syscalls

import "golinux/internal/consts"

func init() {
	register(consts.SYS_exit, sysExit)
	register(consts.SYS_exit_group, sysExitGroup)
}

func sysExit(proc Proc, code, _, _, _, _, _ uint64) (int64, error) {
	return 0, &Stop{Code: int(code) & 0xFF}
}

func sysExitGroup(proc Proc, code, _, _, _, _, _ uint64) (int64, error) {
	return 0, &Stop{Code: int(code) & 0xFF}
}
