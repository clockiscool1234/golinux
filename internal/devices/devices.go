// Package devices implements handlers for the standard character
// devices that live under /dev (null, zero, full, random/urandom,
// tty, console, ptmx), ported from sysemu/devices.py.
//
// These are looked up purely by (major, minor) -- decoded from the
// rdev recorded in the VFS metadata for the node, the same numbers
// vfs.EnsureDevfs() assigned when it created them -- so a guest
// program that mknod()s its own /dev/null-alike with the right
// numbers would also get sensible behavior, matching how a real
// kernel driver table works.
package devices

import (
	"crypto/rand"

	"golinux/internal/errno"
	"golinux/internal/fds"
)

// Proc is everything device handlers need from the owning process.
type Proc interface {
	Fds() *fds.Table
}

func majorMinor(rdev int) (int, int) {
	return (rdev >> 8) & 0xFFF, rdev & 0xFF
}

// Open returns a fds-compatible object for a chr device node, or
// ok=false if this (major, minor) isn't one this package models --
// callers should fall back to treating it as an inert file in that
// case.
func Open(guestPath string, rdev int, proc Proc) (fds.File, bool) {
	major, minor := majorMinor(rdev)

	switch {
	case major == 1 && minor == 3: // /dev/null
		return fds.NewStreamDev("null",
			func(n int) ([]byte, error) { return nil, nil },
			func(d []byte) (int, error) { return len(d), nil },
		), true

	case major == 1 && minor == 5: // /dev/zero
		return fds.NewStreamDev("zero",
			func(n int) ([]byte, error) { return make([]byte, n), nil },
			func(d []byte) (int, error) { return len(d), nil },
		), true

	case major == 1 && minor == 7: // /dev/full
		return fds.NewStreamDev("full",
			func(n int) ([]byte, error) { return make([]byte, n), nil },
			func(d []byte) (int, error) { return 0, &fds.ErrnoError{Errno: errno.ENOSPC} },
		), true

	case major == 1 && (minor == 8 || minor == 9): // /dev/random, /dev/urandom
		name := "random"
		if minor == 9 {
			name = "urandom"
		}
		return fds.NewStreamDev(name,
			func(n int) ([]byte, error) {
				b := make([]byte, n)
				_, _ = rand.Read(b)
				return b, nil
			},
			func(d []byte) (int, error) { return len(d), nil },
		), true

	case major == 5 && (minor == 0 || minor == 1): // /dev/tty, /dev/console
		name := "tty"
		if minor == 1 {
			name = "console"
		}
		stdin := proc.Fds().Get(0)
		stdout := proc.Fds().Get(1)
		readFn := func(n int) ([]byte, error) {
			if stdin != nil {
				return stdin.Read(n)
			}
			return nil, nil
		}
		writeFn := func(d []byte) (int, error) {
			if stdout != nil {
				return stdout.Write(d)
			}
			return len(d), nil
		}
		return fds.NewStreamDev(name, readFn, writeFn), true

	case major == 5 && minor == 2: // /dev/ptmx -- no real pty allocation, just a sink
		return fds.NewStreamDev("ptmx",
			func(n int) ([]byte, error) { return nil, nil },
			func(d []byte) (int, error) { return len(d), nil },
		), true
	}

	return nil, false
}
