// signal.go: rt_sigaction/rt_sigprocmask/rt_sigreturn/kill/tgkill are
// stubbed to report success without doing anything, rather than left
// unimplemented (-ENOSYS), because most programs treat a failed
// sigaction/sigprocmask as fatal during startup even when they'd have
// coped fine with the signal never actually arriving. What's missing
// is the actual delivery mechanism: sysemu/emulator.py has a
// sigtramp/context-switch path that pushes a guest signal frame and
// redirects RIP into the registered handler when a signal fires; this
// port doesn't have that machinery yet, so registered handlers are
// recorded nowhere and never invoked. kill()/tgkill() targeting the
// guest's own pid, in particular, silently do nothing rather than
// actually terminating anything -- a real implementation should at
// least honor SIGKILL/SIGTERM against self by raising *syscalls.Stop.
package syscalls

import "golinux/internal/consts"

func init() {
	register(consts.SYS_rt_sigaction, sysRtSigaction)
	register(consts.SYS_rt_sigprocmask, sysRtSigprocmask)
	register(consts.SYS_rt_sigreturn, sysRtSigreturn)
	register(consts.SYS_kill, sysKill)
	register(consts.SYS_tgkill, sysTgkill)
}

func sysRtSigaction(proc Proc, _, _, _, _, _, _ uint64) (int64, error)   { return 0, nil }
func sysRtSigprocmask(proc Proc, _, _, _, _, _, _ uint64) (int64, error) { return 0, nil }
func sysRtSigreturn(proc Proc, _, _, _, _, _, _ uint64) (int64, error)   { return 0, nil }

func sysKill(proc Proc, pid, sig, _, _, _, _ uint64) (int64, error) {
	return 0, nil
}

func sysTgkill(proc Proc, tgid, tid, sig, _, _, _ uint64) (int64, error) {
	return 0, nil
}
