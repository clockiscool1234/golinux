//go:build !linux

package syscalls

import (
	"golinux/internal/errno"
)

func unsupportedSocket(Proc, uint64, uint64, uint64, uint64, uint64, uint64) (int64, error) {
	return int64(-errno.ENOSYS), nil
}

func sysSocket(p Proc, a, b, c, d, e, f uint64) (int64, error) {
	return unsupportedSocket(p, a, b, c, d, e, f)
}
func sysConnect(p Proc, a, b, c, d, e, f uint64) (int64, error) {
	return unsupportedSocket(p, a, b, c, d, e, f)
}
func sysBind(p Proc, a, b, c, d, e, f uint64) (int64, error) {
	return unsupportedSocket(p, a, b, c, d, e, f)
}
func sysListen(p Proc, a, b, c, d, e, f uint64) (int64, error) {
	return unsupportedSocket(p, a, b, c, d, e, f)
}
func sysAccept(p Proc, a, b, c, d, e, f uint64) (int64, error) {
	return unsupportedSocket(p, a, b, c, d, e, f)
}
func sysGetsockname(p Proc, a, b, c, d, e, f uint64) (int64, error) {
	return unsupportedSocket(p, a, b, c, d, e, f)
}
func sysGetpeername(p Proc, a, b, c, d, e, f uint64) (int64, error) {
	return unsupportedSocket(p, a, b, c, d, e, f)
}
func sysSendto(p Proc, a, b, c, d, e, f uint64) (int64, error) {
	return unsupportedSocket(p, a, b, c, d, e, f)
}
func sysRecvfrom(p Proc, a, b, c, d, e, f uint64) (int64, error) {
	return unsupportedSocket(p, a, b, c, d, e, f)
}
func sysShutdown(p Proc, a, b, c, d, e, f uint64) (int64, error) {
	return unsupportedSocket(p, a, b, c, d, e, f)
}
func sysSocketpair(p Proc, a, b, c, d, e, f uint64) (int64, error) {
	return unsupportedSocket(p, a, b, c, d, e, f)
}
func sysSetsockopt(p Proc, a, b, c, d, e, f uint64) (int64, error) {
	return unsupportedSocket(p, a, b, c, d, e, f)
}
func sysGetsockopt(p Proc, a, b, c, d, e, f uint64) (int64, error) {
	return unsupportedSocket(p, a, b, c, d, e, f)
}
func sysSendmsg(p Proc, a, b, c, d, e, f uint64) (int64, error) {
	return unsupportedSocket(p, a, b, c, d, e, f)
}
func sysRecvmsg(p Proc, a, b, c, d, e, f uint64) (int64, error) {
	return unsupportedSocket(p, a, b, c, d, e, f)
}
