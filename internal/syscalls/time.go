package syscalls

import (
	"crypto/rand"
	"encoding/binary"
	"time"

	"golinux/internal/consts"
	"golinux/internal/errno"
)

func init() {
	register(consts.SYS_gettimeofday, sysGettimeofday)
	register(consts.SYS_time, sysTime)
	register(consts.SYS_clock_gettime, sysClockGettime)
	register(consts.SYS_clock_getres, sysClockGetres)
	register(consts.SYS_nanosleep, sysNanosleep)
	register(consts.SYS_getrandom, sysGetrandom)
	register(consts.SYS_getitimer, sysGetitimer)
	register(consts.SYS_setitimer, sysSetitimer)
	register(consts.SYS_alarm, sysAlarm)
}

func writeTimespecLike(proc Proc, addr uint64, sec, subsec int64) error {
	buf := make([]byte, 16)
	binary.LittleEndian.PutUint64(buf[0:8], uint64(sec))
	binary.LittleEndian.PutUint64(buf[8:16], uint64(subsec))
	return proc.MemWrite(addr, buf)
}

func sysGettimeofday(proc Proc, tv, _tz, _, _, _, _ uint64) (int64, error) {
	if tv != 0 {
		now := time.Now()
		if err := writeTimespecLike(proc, tv, now.Unix(), int64(now.Nanosecond()/1000)); err != nil {
			return int64(-errno.EFAULT), nil
		}
	}
	return 0, nil
}

func sysTime(proc Proc, tloc, _, _, _, _, _ uint64) (int64, error) {
	now := time.Now().Unix()
	if tloc != 0 {
		buf := make([]byte, 8)
		binary.LittleEndian.PutUint64(buf, uint64(now))
		if err := proc.MemWrite(tloc, buf); err != nil {
			return int64(-errno.EFAULT), nil
		}
	}
	return now, nil
}

func sysClockGettime(proc Proc, clkID, ts, _, _, _, _ uint64) (int64, error) {
	now := time.Now()
	if err := writeTimespecLike(proc, ts, now.Unix(), int64(now.Nanosecond())); err != nil {
		return int64(-errno.EFAULT), nil
	}
	return 0, nil
}

func sysClockGetres(proc Proc, clkID, ts, _, _, _, _ uint64) (int64, error) {
	if ts != 0 {
		if err := writeTimespecLike(proc, ts, 0, 1); err != nil {
			return int64(-errno.EFAULT), nil
		}
	}
	return 0, nil
}

// sysNanosleep returns instantly rather than actually blocking the
// host thread, matching sysemu/syscalls.py's sys_nanosleep: a real
// sleep here would stall this whole single-threaded emulator, not
// just the guest "process" that asked for it.
func sysNanosleep(proc Proc, req, rem, _, _, _, _ uint64) (int64, error) {
	return 0, nil
}

func sysGetrandom(proc Proc, buf, buflen, _flags, _, _, _ uint64) (int64, error) {
	data := make([]byte, buflen)
	if _, err := rand.Read(data); err != nil {
		return int64(-errno.EIO), nil
	}
	if err := proc.MemWrite(buf, data); err != nil {
		return int64(-errno.EFAULT), nil
	}
	return int64(len(data)), nil
}

// --------------------------------------------------------------------------
// interval timers (getitimer/setitimer/alarm)
// --------------------------------------------------------------------------

// itimerVal is struct itimerval: two struct timevals (interval, then
// value), each 8 bytes (seconds + microseconds) -- 32 bytes total.
// Layout is identical between guest and host.
const itimerValSize = 32

// readItimerval reads an itimerval out of guest memory. Returns
// (intervalSec, intervalUsec, valueSec, valueUsec, ok).
func readItimerval(proc Proc, ptr uint64) (int64, int64, int64, int64, bool) {
	if ptr == 0 {
		return 0, 0, 0, 0, true
	}
	buf, err := proc.MemRead(ptr, itimerValSize)
	if err != nil {
		return 0, 0, 0, 0, false
	}
	r := func(off int) int64 {
		return int64(binary.LittleEndian.Uint64(buf[off : off+8]))
	}
	return r(0), r(8), r(16), r(24), true
}

// writeItimerval writes a zeroed itimerval (the kernel's reply when no
// timer was previously set -- which is always the case here).
func writeItimerval(proc Proc, ptr uint64) error {
	if ptr == 0 {
		return nil
	}
	return proc.MemWrite(ptr, make([]byte, itimerValSize))
}

// Timer delivery isn't modeled (see signal.go: registered handlers
// are never invoked), so the interval timers are bookkeeping-only:
// setitimer accepts and records nothing, getitimer always reports "no
// timer", and alarm() always reports "no previous alarm". Programs
// that set an ITIMER_REAL and poll with getitimer would see the timer
// never expire; programs that block in select/poll with a timeout
// still time out correctly because the wait itself honors timeouts.
// musl's getitimer/setitimer users (and busybox wget's progress ring
// via setitimer(..., ITIMER_REAL)) only need the calls to succeed.

// ITIMER_* values from linux (shared with the guest ABI).
const (
	itimerReal    = 0
	itimerVirtual = 1
	itimerProf    = 2
)

func sysGetitimer(proc Proc, which, currVal, _, _, _, _ uint64) (int64, error) {
	if int(which) < itimerReal || int(which) > itimerProf {
		return int64(-errno.EINVAL), nil
	}
	if err := writeItimerval(proc, currVal); err != nil {
		return int64(-errno.EFAULT), nil
	}
	return 0, nil
}

func sysSetitimer(proc Proc, which, newVal, oldVal, _, _, _ uint64) (int64, error) {
	if int(which) < itimerReal || int(which) > itimerProf {
		return int64(-errno.EINVAL), nil
	}
	if _, _, _, _, ok := readItimerval(proc, newVal); !ok {
		return int64(-errno.EFAULT), nil
	}
	if err := writeItimerval(proc, oldVal); err != nil {
		return int64(-errno.EFAULT), nil
	}
	return 0, nil
}

// sysAlarm is alarm(seconds) -- setitimer(ITIMER_REAL)'s classic
// shorthand. It returns the seconds remaining on any previous alarm
// (always 0 here, since no timer is ever armed), like the kernel
// would when no prior alarm existed.
func sysAlarm(proc Proc, seconds, _, _, _, _, _ uint64) (int64, error) {
	return 0, nil
}
