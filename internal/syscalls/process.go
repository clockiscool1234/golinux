package syscalls

import (
	"encoding/binary"
	"os"
	"syscall"

	"golinux/internal/consts"
	"golinux/internal/errno"
)

func init() {
	register(consts.SYS_getpid, sysGetpid)
	register(consts.SYS_getppid, sysGetppid)
	register(consts.SYS_getpgrp, sysGetpgrp)
	register(consts.SYS_getpgid, sysGetpgid)
	register(consts.SYS_setpgid, sysSetpgid)
	register(consts.SYS_getsid, sysGetsid)
	register(consts.SYS_setsid, sysSetsid)
	register(consts.SYS_gettid, sysGetpid) // single-threaded guest: tid == pid
	register(consts.SYS_getuid, sysGetuid)
	register(consts.SYS_getgid, sysGetgid)
	register(consts.SYS_geteuid, sysGeteuid)
	register(consts.SYS_getegid, sysGetegid)
	register(consts.SYS_setuid, sysSetuid)
	register(consts.SYS_setgid, sysSetgid)
	register(consts.SYS_setreuid, sysSetreuid)
	register(consts.SYS_setregid, sysSetregid)
	register(consts.SYS_setresuid, sysSetresuid)
	register(consts.SYS_getresuid, sysGetresuid)
	register(consts.SYS_setresgid, sysSetresgid)
	register(consts.SYS_getresgid, sysGetresgid)
	register(consts.SYS_setfsuid, sysSetfsuid)
	register(consts.SYS_setfsgid, sysSetfsgid)
	register(consts.SYS_getgroups, sysGetgroups)
	register(consts.SYS_setgroups, sysSetgroups)
	register(consts.SYS_uname, sysUname)
	register(consts.SYS_sched_yield, sysSchedYield)
	register(consts.SYS_sched_getaffinity, sysSchedGetaffinity)
}

// --------------------------------------------------------------------------
// pid / process-group / session
//
// Guest pids used to always be real host pids (this Go process's own
// pid), since multi-process guest trees weren't modeled. fork() (see
// fork.go) changes that: a forked child gets a synthetic pid, not a
// real one, because it's still just another goroutine inside this
// same host OS process, not a separate one the host kernel knows
// about.
//
// The process-group/session calls below still need to ask the *real*
// kernel, though -- that's what lets job control (TIOCSPGRP/
// TIOCGPGRP, Ctrl-Z, etc.) work against the real terminal driver
// instead of being a fiction the tty never hears about. So "self"
// (pid <= 0) here always resolves to os.Getpid(), the one real host
// process backing every guest process/goroutine in this run, rather
// than proc.Pid() -- which, for a forked child, wouldn't correspond
// to any real process the host kernel could look up.
// --------------------------------------------------------------------------

func sysGetpid(proc Proc, _, _, _, _, _, _ uint64) (int64, error) {
	return int64(proc.Pid()), nil
}

func sysGetppid(proc Proc, _, _, _, _, _, _ uint64) (int64, error) {
	if ppid := proc.Ppid(); ppid != 0 {
		return int64(ppid), nil
	}
	return 1, nil // the root process has no guest parent; report pid 1, as if reparented to init
}

func sysGetpgrp(proc Proc, _, _, _, _, _, _ uint64) (int64, error) {
	pgid, err := syscall.Getpgid(0)
	if err != nil {
		return int64(-errnoOf(err)), nil
	}
	return int64(pgid), nil
}

func sysGetpgid(proc Proc, pid, _, _, _, _, _ uint64) (int64, error) {
	realPid := int(int32(pid))
	if realPid <= 0 {
		realPid = os.Getpid()
	}
	pgid, err := syscall.Getpgid(realPid)
	if err != nil {
		return int64(-errnoOf(err)), nil
	}
	return int64(pgid), nil
}

func sysSetpgid(proc Proc, pid, pgid, _, _, _, _ uint64) (int64, error) {
	realPid := int(int32(pid))
	if realPid <= 0 {
		realPid = os.Getpid()
	}
	realPgid := int(int32(pgid))
	if realPgid <= 0 {
		realPgid = realPid
	}
	if err := syscall.Setpgid(realPid, realPgid); err != nil {
		return int64(-errnoOf(err)), nil
	}
	return 0, nil
}

func sysGetsid(proc Proc, pid, _, _, _, _, _ uint64) (int64, error) {
	realPid := int(int32(pid))
	if realPid <= 0 {
		realPid = os.Getpid()
	}
	// syscall.Getsid isn't wrapped by the Go standard library on
	// linux/amd64 (unlike Getpgid/Setpgid/Setsid); go straight to the
	// raw syscall number instead of pulling in golang.org/x/sys/unix
	// for one call.
	sid, _, errno1 := syscall.Syscall(syscall.SYS_GETSID, uintptr(realPid), 0, 0)
	if errno1 != 0 {
		return int64(-int(errno1)), nil
	}
	return int64(sid), nil
}

func sysSetsid(proc Proc, _, _, _, _, _, _ uint64) (int64, error) {
	pid, err := syscall.Setsid()
	if err != nil {
		return int64(-errnoOf(err)), nil
	}
	return int64(pid), nil
}

func errnoOf(err error) int {
	if e, ok := err.(syscall.Errno); ok {
		return int(e)
	}
	return errno.EIO
}

// --------------------------------------------------------------------------
// credentials: getuid/getgid/... family
// --------------------------------------------------------------------------

func sysGetuid(proc Proc, _, _, _, _, _, _ uint64) (int64, error)  { return int64(proc.Uid()), nil }
func sysGetgid(proc Proc, _, _, _, _, _, _ uint64) (int64, error)  { return int64(proc.Gid()), nil }
func sysGeteuid(proc Proc, _, _, _, _, _, _ uint64) (int64, error) { return int64(proc.Euid()), nil }
func sysGetegid(proc Proc, _, _, _, _, _, _ uint64) (int64, error) { return int64(proc.Egid()), nil }

// --------------------------------------------------------------------------
// credentials: setuid/setgid family (su, passwd, adduser)
//
// NOTE: these update the bookkeeping fields on Process (so getuid()/id/
// whoami and su's own success check behave correctly) but do not add
// real kernel-style permission *enforcement* to file access -- every
// guest syscall still reaches the real host filesystem as whatever
// user actually runs this emulator process. See the identical note in
// sysemu/syscalls.py.
// --------------------------------------------------------------------------

const u32Max = 0xFFFFFFFF

func sysSetuid(proc Proc, uid, _, _, _, _, _ uint64) (int64, error) {
	u := uint32(uid)
	proc.SetUid(u)
	proc.SetEuid(u)
	proc.SetFsuid(u)
	proc.SetSuid(u)
	return 0, nil
}

func sysSetgid(proc Proc, gid, _, _, _, _, _ uint64) (int64, error) {
	g := uint32(gid)
	proc.SetGid(g)
	proc.SetEgid(g)
	proc.SetFsgid(g)
	proc.SetSgid(g)
	return 0, nil
}

func sysSetreuid(proc Proc, ruid, euid, _, _, _, _ uint64) (int64, error) {
	r, e := uint32(ruid), uint32(euid)
	if r != u32Max {
		proc.SetUid(r)
	}
	if e != u32Max {
		proc.SetEuid(e)
		proc.SetFsuid(e)
	}
	return 0, nil
}

func sysSetregid(proc Proc, rgid, egid, _, _, _, _ uint64) (int64, error) {
	r, e := uint32(rgid), uint32(egid)
	if r != u32Max {
		proc.SetGid(r)
	}
	if e != u32Max {
		proc.SetEgid(e)
		proc.SetFsgid(e)
	}
	return 0, nil
}

func sysSetresuid(proc Proc, ruid, euid, suid, _, _, _ uint64) (int64, error) {
	r, e, s := uint32(ruid), uint32(euid), uint32(suid)
	if r != u32Max {
		proc.SetUid(r)
	}
	if e != u32Max {
		proc.SetEuid(e)
		proc.SetFsuid(e)
	}
	if s != u32Max {
		proc.SetSuid(s)
	}
	return 0, nil
}

func sysGetresuid(proc Proc, ruidPtr, euidPtr, suidPtr, _, _, _ uint64) (int64, error) {
	writeU32(proc, ruidPtr, proc.Uid())
	writeU32(proc, euidPtr, proc.Euid())
	writeU32(proc, suidPtr, proc.Suid())
	return 0, nil
}

func sysSetresgid(proc Proc, rgid, egid, sgid, _, _, _ uint64) (int64, error) {
	r, e, s := uint32(rgid), uint32(egid), uint32(sgid)
	if r != u32Max {
		proc.SetGid(r)
	}
	if e != u32Max {
		proc.SetEgid(e)
		proc.SetFsgid(e)
	}
	if s != u32Max {
		proc.SetSgid(s)
	}
	return 0, nil
}

func sysGetresgid(proc Proc, rgidPtr, egidPtr, sgidPtr, _, _, _ uint64) (int64, error) {
	writeU32(proc, rgidPtr, proc.Gid())
	writeU32(proc, egidPtr, proc.Egid())
	writeU32(proc, sgidPtr, proc.Sgid())
	return 0, nil
}

func sysSetfsuid(proc Proc, fsuid, _, _, _, _, _ uint64) (int64, error) {
	old := proc.Fsuid()
	u := uint32(fsuid)
	if u != u32Max {
		proc.SetFsuid(u)
	}
	return int64(old), nil
}

func sysSetfsgid(proc Proc, fsgid, _, _, _, _, _ uint64) (int64, error) {
	old := proc.Fsgid()
	g := uint32(fsgid)
	if g != u32Max {
		proc.SetFsgid(g)
	}
	return int64(old), nil
}

func sysGetgroups(proc Proc, size, listPtr, _, _, _, _ uint64) (int64, error) {
	groups := proc.Groups()
	if size == 0 {
		return int64(len(groups)), nil
	}
	if int(size) < len(groups) {
		return int64(-errno.EINVAL), nil
	}
	buf := make([]byte, len(groups)*4)
	for i, g := range groups {
		binary.LittleEndian.PutUint32(buf[i*4:i*4+4], g)
	}
	if err := proc.MemWrite(listPtr, buf); err != nil {
		return int64(-errno.EFAULT), nil
	}
	return int64(len(groups)), nil
}

func sysSetgroups(proc Proc, size, listPtr, _, _, _, _ uint64) (int64, error) {
	if size == 0 {
		proc.SetGroups(nil)
		return 0, nil
	}
	data, err := proc.MemRead(listPtr, int(size)*4)
	if err != nil {
		return int64(-errno.EFAULT), nil
	}
	groups := make([]uint32, size)
	for i := range groups {
		groups[i] = binary.LittleEndian.Uint32(data[i*4 : i*4+4])
	}
	proc.SetGroups(groups)
	return 0, nil
}

func writeU32(proc Proc, addr uint64, v uint32) {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, v)
	_ = proc.MemWrite(addr, buf)
}

// --------------------------------------------------------------------------
// uname / scheduling
// --------------------------------------------------------------------------

func sysUname(proc Proc, buf, _, _, _, _, _ uint64) (int64, error) {
	fields := []string{"Linux", proc.Hostname(), "6.6.0-emu", "#1 SMP", "x86_64", ""}
	blob := make([]byte, 0, 65*6)
	for _, f := range fields {
		field := make([]byte, 65)
		copy(field, f)
		blob = append(blob, field...)
	}
	if err := proc.MemWrite(buf, blob); err != nil {
		return int64(-errno.EFAULT), nil
	}
	return 0, nil
}

func sysSchedYield(proc Proc, _, _, _, _, _, _ uint64) (int64, error) {
	return 0, nil
}

func sysSchedGetaffinity(proc Proc, pid, cpusetsize, maskPtr, _, _, _ uint64) (int64, error) {
	// Report a single-CPU affinity mask -- this emulator never
	// schedules the guest across more than one (fake) CPU.
	if maskPtr != 0 && cpusetsize > 0 {
		buf := make([]byte, cpusetsize)
		buf[0] = 1
		if err := proc.MemWrite(maskPtr, buf); err != nil {
			return int64(-errno.EFAULT), nil
		}
	}
	return int64(cpusetsize), nil
}
