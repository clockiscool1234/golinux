//go:build darwin

package syscalls

import "golinux/internal/errno"

func hostIoctl(hostFd uintptr, request uint64, buf []byte) int { return errno.ENOTTY }
