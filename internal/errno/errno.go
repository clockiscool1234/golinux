// Package errno holds Linux x86_64 errno values (subset actually used by
// the emulator), ported from sysemu/errno.py.
//
// Syscall return convention on Linux/x86_64: on error the kernel returns
// -errno (a small negative number) in rax, not -1 + a separate errno
// variable (that's the libc wrapper's job, which we don't have here
// since we ARE the kernel). So everywhere in this codebase a syscall
// implementation that fails returns -EFOO.
package errno

const (
	EPERM     = 1
	ENOENT    = 2
	ESRCH     = 3
	EINTR     = 4
	EIO       = 5
	ENXIO     = 6
	E2BIG     = 7
	ENOEXEC   = 8
	EBADF     = 9
	ECHILD    = 10
	EAGAIN    = 11
	ENOMEM    = 12
	EACCES    = 13
	EFAULT    = 14
	ENOTBLK   = 15
	EBUSY     = 16
	EEXIST    = 17
	EXDEV     = 18
	ENODEV    = 19
	ENOTDIR   = 20
	EISDIR    = 21
	EINVAL    = 22
	ENFILE    = 23
	EMFILE    = 24
	ENOTTY    = 25
	EFBIG     = 27
	ENOSPC    = 28
	ESPIPE    = 29
	EROFS     = 30
	EMLINK    = 31
	EPIPE     = 32
	ERANGE    = 34
	ENOSYS    = 38
	ENOTEMPTY = 39
	ELOOP     = 40
	ENODATA   = 61
	EOVERFLOW = 75
)

// --- socket/network errnos (used by the optional networking layer) -------
const (
	ENOMSG          = 42
	ENOTSOCK        = 88
	EDESTADDRREQ    = 89
	EMSGSIZE        = 90
	EPROTOTYPE      = 91
	ENOPROTOOPT     = 92
	EPROTONOSUPPORT = 93
	ESOCKTNOSUPPORT = 94
	EOPNOTSUPP      = 95
	EAFNOSUPPORT    = 97
	EADDRINUSE      = 98
	EADDRNOTAVAIL   = 99
	ENETDOWN        = 100
	ENETUNREACH     = 101
	ENETRESET       = 102
	ECONNABORTED    = 103
	ECONNRESET      = 104
	ENOBUFS         = 105
	EISCONN         = 106
	ENOTCONN        = 107
	ESHUTDOWN       = 108
	ETOOMANYREFS    = 109
	ETIMEDOUT       = 110
	ECONNREFUSED    = 111
	EHOSTDOWN       = 112
	EHOSTUNREACH    = 113
	EALREADY        = 114
	EINPROGRESS     = 115
)
