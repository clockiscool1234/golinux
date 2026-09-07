// Package consts holds x86_64 Linux ABI constants: syscall numbers and
// flag bits, ported from sysemu/consts.py.
//
// Only the syscalls this emulator implements are named individually;
// everything else falls through to a generic "unimplemented" handler
// in the syscalls package that logs the number and returns -ENOSYS
// instead of crashing, so unfamiliar programs fail loudly-but-
// gracefully instead of silently corrupting state.
package consts

// --- syscall numbers (x86_64) -------------------------------------------
const (
	SYS_read              = 0
	SYS_write             = 1
	SYS_open              = 2
	SYS_close             = 3
	SYS_stat              = 4
	SYS_fstat             = 5
	SYS_lstat             = 6
	SYS_poll              = 7
	SYS_lseek             = 8
	SYS_mmap              = 9
	SYS_mprotect          = 10
	SYS_munmap            = 11
	SYS_brk               = 12
	SYS_rt_sigaction      = 13
	SYS_rt_sigprocmask    = 14
	SYS_rt_sigreturn      = 15
	SYS_ioctl             = 16
	SYS_pread64           = 17
	SYS_pwrite64          = 18
	SYS_readv             = 19
	SYS_writev            = 20
	SYS_access            = 21
	SYS_pipe              = 22
	SYS_select            = 23
	SYS_sched_yield       = 24
	SYS_dup               = 32
	SYS_dup2              = 33
	SYS_nanosleep         = 35
	SYS_getpid            = 39
	SYS_socket            = 41
	SYS_clone             = 56
	SYS_fork              = 57
	SYS_vfork             = 58
	SYS_execve            = 59
	SYS_exit              = 60
	SYS_wait4             = 61
	SYS_kill              = 62
	SYS_uname             = 63
	SYS_fcntl             = 72
	SYS_flock             = 73
	SYS_fsync             = 74
	SYS_ftruncate         = 77
	SYS_getcwd            = 79
	SYS_chdir             = 80
	SYS_rename            = 82
	SYS_mkdir             = 83
	SYS_rmdir             = 84
	SYS_creat             = 85
	SYS_link              = 86
	SYS_unlink            = 87
	SYS_symlink           = 88
	SYS_readlink          = 89
	SYS_chmod             = 90
	SYS_fchown            = 93
	SYS_lchown            = 94
	SYS_chown             = 92
	SYS_umask             = 95
	SYS_gettimeofday      = 96
	SYS_getrlimit         = 97
	SYS_getuid            = 102
	SYS_getgid            = 104
	SYS_setuid            = 105
	SYS_setgid            = 106
	SYS_geteuid           = 107
	SYS_getegid           = 108
	SYS_setpgid           = 109
	SYS_getppid           = 110
	SYS_getpgrp           = 111
	SYS_setsid            = 112
	SYS_setreuid          = 113
	SYS_setregid          = 114
	SYS_getgroups         = 115
	SYS_setgroups         = 116
	SYS_setresuid         = 117
	SYS_getresuid         = 118
	SYS_setresgid         = 119
	SYS_getresgid         = 120
	SYS_getpgid           = 121
	SYS_setfsuid          = 122
	SYS_setfsgid          = 123
	SYS_getsid            = 124
	SYS_statfs            = 137
	SYS_pivot_root        = 155
	SYS_chroot            = 161
	SYS_mount             = 165
	SYS_umount2           = 166
	SYS_sethostname       = 170
	SYS_setdomainname     = 171
	SYS_arch_prctl        = 158
	SYS_sync              = 162
	SYS_gettid            = 186
	SYS_time              = 201
	SYS_futex             = 202
	SYS_sched_getaffinity = 204
	SYS_getdents64        = 217
	SYS_set_tid_address   = 218
	SYS_clock_gettime     = 228
	SYS_clock_getres      = 229
	SYS_exit_group        = 231
	SYS_tgkill            = 234
	SYS_utimes            = 235
	SYS_openat            = 257
	SYS_mkdirat           = 258
	SYS_fstatat           = 262
	SYS_unlinkat          = 263
	SYS_renameat          = 264
	SYS_linkat            = 265
	SYS_readlinkat        = 267
	SYS_faccessat         = 269
	SYS_pselect6          = 270
	SYS_ppoll             = 271
	SYS_set_robust_list   = 273
	SYS_utimensat         = 280
	SYS_prlimit64         = 302
	SYS_getrandom         = 318
	SYS_rseq              = 334
	SYS_faccessat2        = 439
)

// SyscallNames maps a syscall number to its bare name (without the
// "SYS_" prefix), used for verbose logging.
var SyscallNames = map[int]string{
	SYS_read: "read", SYS_write: "write", SYS_open: "open", SYS_close: "close",
	SYS_stat: "stat", SYS_fstat: "fstat", SYS_lstat: "lstat", SYS_poll: "poll",
	SYS_lseek: "lseek", SYS_mmap: "mmap", SYS_mprotect: "mprotect", SYS_munmap: "munmap",
	SYS_brk: "brk", SYS_rt_sigaction: "rt_sigaction", SYS_rt_sigprocmask: "rt_sigprocmask",
	SYS_rt_sigreturn: "rt_sigreturn", SYS_ioctl: "ioctl", SYS_pread64: "pread64",
	SYS_pwrite64: "pwrite64", SYS_readv: "readv", SYS_writev: "writev", SYS_access: "access",
	SYS_pipe: "pipe", SYS_select: "select", SYS_sched_yield: "sched_yield", SYS_dup: "dup",
	SYS_dup2: "dup2", SYS_nanosleep: "nanosleep", SYS_getpid: "getpid", SYS_socket: "socket",
	SYS_clone: "clone", SYS_fork: "fork", SYS_vfork: "vfork", SYS_execve: "execve",
	SYS_exit: "exit", SYS_wait4: "wait4", SYS_kill: "kill", SYS_uname: "uname",
	SYS_fcntl: "fcntl", SYS_flock: "flock", SYS_fsync: "fsync", SYS_ftruncate: "ftruncate",
	SYS_getcwd: "getcwd", SYS_chdir: "chdir", SYS_rename: "rename", SYS_mkdir: "mkdir",
	SYS_rmdir: "rmdir", SYS_creat: "creat", SYS_link: "link", SYS_unlink: "unlink",
	SYS_symlink: "symlink", SYS_readlink: "readlink", SYS_chmod: "chmod",
	SYS_fchown: "fchown", SYS_lchown: "lchown", SYS_chown: "chown", SYS_umask: "umask",
	SYS_gettimeofday: "gettimeofday", SYS_getrlimit: "getrlimit", SYS_getuid: "getuid",
	SYS_getgid: "getgid", SYS_setuid: "setuid", SYS_setgid: "setgid", SYS_geteuid: "geteuid",
	SYS_getegid: "getegid", SYS_setpgid: "setpgid", SYS_getppid: "getppid",
	SYS_getpgrp: "getpgrp", SYS_setsid: "setsid", SYS_setreuid: "setreuid",
	SYS_setregid: "setregid", SYS_getgroups: "getgroups", SYS_setgroups: "setgroups",
	SYS_setresuid: "setresuid", SYS_getresuid: "getresuid", SYS_setresgid: "setresgid",
	SYS_getresgid: "getresgid", SYS_getpgid: "getpgid", SYS_setfsuid: "setfsuid",
	SYS_setfsgid: "setfsgid", SYS_getsid: "getsid", SYS_statfs: "statfs",
	SYS_pivot_root: "pivot_root", SYS_chroot: "chroot", SYS_mount: "mount",
	SYS_umount2: "umount2", SYS_sethostname: "sethostname", SYS_setdomainname: "setdomainname",
	SYS_arch_prctl: "arch_prctl", SYS_sync: "sync", SYS_gettid: "gettid",
	SYS_time: "time", SYS_futex: "futex", SYS_sched_getaffinity: "sched_getaffinity",
	SYS_getdents64: "getdents64", SYS_set_tid_address: "set_tid_address",
	SYS_clock_gettime: "clock_gettime", SYS_clock_getres: "clock_getres",
	SYS_exit_group: "exit_group", SYS_tgkill: "tgkill", SYS_utimes: "utimes",
	SYS_openat: "openat", SYS_mkdirat: "mkdirat", SYS_fstatat: "fstatat",
	SYS_unlinkat: "unlinkat", SYS_renameat: "renameat", SYS_linkat: "linkat",
	SYS_readlinkat: "readlinkat", SYS_faccessat: "faccessat", SYS_pselect6: "pselect6",
	SYS_ppoll: "ppoll", SYS_set_robust_list: "set_robust_list", SYS_utimensat: "utimensat",
	SYS_prlimit64: "prlimit64", SYS_getrandom: "getrandom", SYS_rseq: "rseq",
	SYS_faccessat2: "faccessat2",
}

// --- open(2) flags (Linux x86_64 values) --------------------------------
const (
	O_RDONLY    = 0o0
	O_WRONLY    = 0o1
	O_RDWR      = 0o2
	O_ACCMODE   = 0o3
	O_CREAT     = 0o100
	O_EXCL      = 0o200
	O_NOCTTY    = 0o400
	O_TRUNC     = 0o1000
	O_APPEND    = 0o2000
	O_NONBLOCK  = 0o4000
	O_DIRECTORY = 0o200000
	O_NOFOLLOW  = 0o400000
	O_CLOEXEC   = 0o2000000
)

const (
	AT_FDCWD            = -100
	AT_SYMLINK_NOFOLLOW = 0x100
)

// --- mmap flags ----------------------------------------------------------
const (
	PROT_READ     = 0x1
	PROT_WRITE    = 0x2
	PROT_EXEC     = 0x4
	MAP_SHARED    = 0x01
	MAP_PRIVATE   = 0x02
	MAP_FIXED     = 0x10
	MAP_ANONYMOUS = 0x20
)

// --- stat.st_mode file type bits -----------------------------------------
const (
	S_IFMT   = 0o170000
	S_IFSOCK = 0o140000
	S_IFLNK  = 0o120000
	S_IFREG  = 0o100000
	S_IFBLK  = 0o060000
	S_IFDIR  = 0o040000
	S_IFCHR  = 0o020000
	S_IFIFO  = 0o010000
)

// --- fcntl commands --------------------------------------------------------
const (
	F_DUPFD         = 0
	F_GETFD         = 1
	F_SETFD         = 2
	F_GETFL         = 3
	F_SETFL         = 4
	F_DUPFD_CLOEXEC = 1030
)

// --- rlimit resource numbers used by prlimit64/getrlimit -----------------
const (
	RLIMIT_STACK  = 3
	RLIMIT_NOFILE = 7
	RLIM_INFINITY = (1 << 64) - 1
)

// --- auxv types ------------------------------------------------------------
const (
	AT_NULL         = 0
	AT_PHDR         = 3
	AT_PHENT        = 4
	AT_PHNUM        = 5
	AT_PAGESZ       = 6
	AT_BASE         = 7
	AT_FLAGS        = 8
	AT_ENTRY        = 9
	AT_UID          = 11
	AT_EUID         = 12
	AT_GID          = 13
	AT_EGID         = 14
	AT_HWCAP        = 16
	AT_CLKTCK       = 17
	AT_SECURE       = 23
	AT_RANDOM       = 25
	AT_EXECFN       = 31
	AT_SYSINFO_EHDR = 33
)

const PageSize = 0x1000

// --- tty ioctl requests ----------------------------------------------------
const (
	TCGETS     = 0x5401
	TCSETS     = 0x5402
	TCSETSW    = 0x5403
	TCSETSF    = 0x5404
	TIOCGPGRP  = 0x540F
	TIOCSPGRP  = 0x5410
	TIOCGWINSZ = 0x5413
	TIOCSWINSZ = 0x5414
)

// --- poll(2)/ppoll(2) event/revent bits (linux/amd64 struct pollfd) -------
const (
	POLLIN   = 0x001
	POLLPRI  = 0x002
	POLLOUT  = 0x004
	POLLERR  = 0x008
	POLLHUP  = 0x010
	POLLNVAL = 0x020
)

// Raw kernel struct termios (NCCS=19, no speed fields) is exactly 36
// bytes on Linux/x86_64 -- see asm-generic/termbits.h.
const TermiosSize = 36

// --- signals ---------------------------------------------------------------
const (
	SIGHUP   = 1
	SIGINT   = 2
	SIGQUIT  = 3
	SIGILL   = 4
	SIGTRAP  = 5
	SIGABRT  = 6
	SIGBUS   = 7
	SIGFPE   = 8
	SIGKILL  = 9
	SIGUSR1  = 10
	SIGSEGV  = 11
	SIGUSR2  = 12
	SIGPIPE  = 13
	SIGALRM  = 14
	SIGTERM  = 15
	SIGCHLD  = 17
	SIGCONT  = 18
	SIGSTOP  = 19
	SIGTSTP  = 20
	SIGTTIN  = 21
	SIGTTOU  = 22
	SIGURG   = 23
	SIGWINCH = 28
)

const (
	SIG_DFL = 0
	SIG_IGN = 1
)
