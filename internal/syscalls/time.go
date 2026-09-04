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
