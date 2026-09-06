# golinux

A non-interactive AMD64 Linux syscall emulator, written in Go. It loads
a real x86-64 ELF binary, executes its machine code instruction-by-
instruction through its own custom x86_64 CPU emulator,
and intercepts every syscall to redirect it into a virtual filesystem
instead of the host kernel — the guest program genuinely believes it's
running on Linux, but never touches your real `/`.

This is a Go port of a Python original (`pylinux`). It is not a
drop-in replacement for a container runtime or a VM — there's no
kernel, no real process isolation, no scheduler. Think of it as a
syscall-level sandbox/instrumentation tool, closer in spirit to QEMU
user-mode emulation or `ptrace`-based sandboxes than to Docker.

## How it works

```
 ELF file on host
        │
        ▼
 ┌─────────────┐    parse headers, PT_LOAD segments
 │  elfload    │────────────────────────────────────────────┐
 └─────────────┘                                            │
                                                            ▼
 ┌─────────────┐   map segments, set up stack/auxv,   ┌───────────┐
 │  emulator   │──install SYSCALL/CPUID hooks────────▶│    cpu    │
 │  (Process)  │                                      │  (native  │
 └──────┬──────┘◀─────────────────────────────────────┤ Go x86-64 │
        │        every SYSCALL instruction traps here │  engine)  │
        ▼                                             └───────────┘
 ┌─────────────┐
 │  syscalls   │  ~115 syscall handlers, dispatched by number
 └──────┬──────┘
        │
   ┌────┼─────────────┬─────────────┬─────────────┐
   ▼    ▼             ▼             ▼             ▼
 ┌────┐┌──────┐   ┌────────┐   ┌────────┐    ┌─────────┐
 │vfs ││ fds  │   │ procfs │   │devices │    │  (none) │
 └────┘└──────┘   └────────┘   └────────┘    └─────────┘
  files  fd table  synthetic    /dev/null,
  on      (open     /proc       zero, random,
  disk    files,              tty, etc.
          pipes,
          dirs)
```

**The emulation loop**, at a glance (`internal/emulator`):

1. `elfload` parses the ELF64 header and program header table — no
   dependencies, just byte-slicing.
2. `emulator.Process.Load()` maps each `PT_LOAD` segment into a fresh
   `internal/cpu` engine context (a native, pure-Go x86-64 emulator —
   no cgo, no C toolchain), builds the initial stack (`argv`/`envp`/
   auxv, per the System V x86-64 ABI), and points `RIP` at the entry
   point.
3. `Process.Run()` calls `Engine.EmuStart()`, which decodes and
   executes real machine code instruction-by-instruction until it
   hits a `syscall` or `cpuid` instruction, which traps into a Go
   callback via a hook.
4. The `syscall` trap reads the syscall number and six arguments
   straight out of the guest's registers (`rax`, `rdi`, `rsi`, `rdx`,
   `r10`, `r8`, `r9` — the Linux x86-64 syscall calling convention),
   and hands them to `syscalls.Dispatch`.
5. Each handler in `internal/syscalls` does whatever a real kernel
   would — read guest memory, touch the virtual filesystem, mutate the
   file descriptor table — and returns a value that gets written back
   into `rax`, exactly like the kernel would on `sysret`.
6. `exit`/`exit_group` unwind out of the loop via a typed error
   (`*syscalls.Stop`); `execve` unwinds the same way (`*syscalls.
   Execve`) and the loop rebuilds the process image in place with a
   fresh engine context; `fork`/`vfork`/`clone` unwind similarly
   (`*syscalls.Fork`) but — unlike `execve` — the *parent* just
   continues in the same loop, since only a *new*, independent process
   needs spinning up (see "Multi-process support" below).

### The virtual filesystem (`internal/vfs`)

Guest directories map 1:1 onto real host directories under a root you
choose (`--vfs-root`); regular file *content* is just stored as an
ordinary host file, so reading/writing bytes is fast and simple.

What's **not** delegated to the host filesystem is metadata — uid,
gid, mode, and symlinks are tracked in a JSON sidecar file
(`.golinux_meta`) placed in every directory, rather than relying on
`chown`/`chmod`/real symlinks. This means:

- You never need root to make a guest file "owned by root".
- A vfs root is 100% portable — copy the directory tree anywhere
  (including to a different OS) and it behaves identically.
- Symlinks are pure metadata (no real symlink is ever created on the
  host), so they can't accidentally escape the vfs root or trip up
  tooling that's cautious around symlinks.

Every guest path — relative or absolute, `.`/`..` and all — is
canonicalized (`vfs.NormPath`) before it's compared against anything,
including the mount table, so `stat("proc")`, `stat("/proc")`, and
`stat("./proc")` all agree once `proc` is `mount -t proc`'d, no matter
the guest's current working directory.

### Multi-process support (`fork`/`vfork`/`clone`/`wait4`)

`fork()`, `vfork()`, and the process-shaped forms of `clone()` (no
`CLONE_VM`/`CLONE_THREAD`) are implemented, along with a real, blocking
`wait4()` — but not via the host's own `fork(2)`, which doesn't mix
safely with Go's multi-threaded runtime (see `internal/syscalls/
fork.go`'s doc comment for the full reasoning). Instead, since a
"process" here is already just CPU state (registers + a page table)
interpreted by `internal/cpu` rather than something the host kernel
schedules, forking deep-copies that state (`cpu.Engine.Clone`, `fds.
Table.Clone`) into a new logical process and runs it forward on its
own goroutine. Parent and child are then genuinely independent
goroutines — a blocking read in the child only blocks that goroutine,
never the parent or any siblings.

A few deliberate, documented simplifications come with this design
(all safe — never wrong, just not a 1:1 match for every corner of real
semantics):

- `vfork()` gets a full independent copy, same as `fork()`, rather
  than a shared address space with the parent suspended until the
  child execs or exits. Correct for the fork-then-exec idiom this
  exists to serve; just not the performance optimization real `vfork`
  is.
- Real thread creation (`pthread_create`, i.e. `clone()` with both
  `CLONE_VM` and `CLONE_THREAD`) isn't implemented — that needs actual
  shared memory between logical processes, a bigger feature than
  process-shaped fork. Reports `ENOSYS`.
- Forked children get synthetic pids (real host pids aren't available
  for something that's still just a goroutine in this same OS
  process), and if the root process exits while a child is still
  running, that child is abandoned along with the rest of the Go
  process — there's no init here to re-parent orphans to.

### Synthetic `/proc` and `/dev` (`internal/procfs`, `internal/devices`)

Once the guest `mount -t proc proc /proc`s (or the CLI auto-mounts it
at startup), reads under that mountpoint are generated on the fly from
live process state instead of touching disk — `/proc/version`,
`/proc/self/status`, `/proc/mounts`, etc. Device nodes under `/dev`
(`null`, `zero`, `full`, `random`/`urandom`, `tty`, `console`, `ptmx`)
are looked up by the (major, minor) numbers recorded on the node and
handled as in-memory pseudo-devices.

### What's implemented

~115 syscalls across file I/O, filesystem metadata, directory
operations, memory management (`brk`/`mmap`/`mprotect`), multi-process
support (`fork`/`vfork`/`clone`/`wait4`, see above), process/identity
introspection, time, terminal control, and mount table management —
see the doc comment at the top of `internal/syscalls/syscalls.go` for
the full category breakdown and exactly what's stubbed vs. real.

`ioctl` is implemented for the requests that matter for a guest
program to behave sanely in a terminal: `TCGETS`/`TCSETS`/`TCSETSW`/
`TCSETSF`, `TIOCGWINSZ`/`TIOCSWINSZ`, and `TIOCGPGRP`/`TIOCSPGRP` —
forwarded to the real underlying terminal for stdin/stdout/stderr, so
`isatty()` (which both musl and glibc implement as exactly "does
`ioctl(fd, TCGETS, &buf)` succeed?") gives a correct answer, and
interactive shells behave properly (printing a prompt, etc.) when
actually run under a real terminal. Every other `ioctl` request reports
`ENOTTY`/`ENOSYS` as appropriate rather than silently lying.

**Deliberately not implemented yet**, each for a specific reason
documented in the corresponding file:

- **Real signal delivery** (`signal.go`) — `sigaction`/`sigprocmask`
  etc. report success so guest startup doesn't abort, but no sigtramp/
  context-switch machinery exists yet to actually invoke a registered
  handler.
- **`poll`/`select`/`ppoll`/`pselect6`** — need real multiplexed I/O
  across the fd table; reports `ENOSYS` rather than a fake stub that
  would make callers spin or hang confusingly. Interactive shells with
  a real terminal attached (see `ioctl` above) are more likely to hit
  this now than before, since `isatty()` succeeding unlocks line-
  editing/job-control code paths that a program previously skipped
  entirely when it believed it wasn't attached to a terminal.
- **Sockets** — not started.

## Building

### Requirements

- **Go 1.25+**

That's it for building and running `golinux` itself: `internal/cpu`,
the native pure-Go x86-64 engine, is what `internal/emulator` actually
uses now, and it has no cgo or C-toolchain dependency.

`internal/uc` — the original cgo binding to `libunicorn` that
`internal/cpu` was built to replace — is still in the tree as a
drop-in alternative backend (see its and `internal/cpu`'s doc
comments), but nothing imports it anymore. It's only pulled in by
`go build ./...`/`go test ./...`/`go vet ./...` when they cover the
whole module rather than just `./cmd/golinux`, so if you want to
build or test *everything* (including `internal/uc`'s own tests),
you'll additionally need:

- **A C compiler** (cgo needs one) — `gcc` or `clang`
- **libunicorn 2.x**, headers and shared library (`pkg-config unicorn`
  must resolve)

On Debian/Ubuntu:

```bash
# golinux itself:
sudo apt-get install -y golang-go
# plus, only if building/testing the whole module (internal/uc):
sudo apt-get install -y gcc pkg-config libunicorn-dev
```

On macOS (via Homebrew):

```bash
brew install go
# plus, only if building/testing the whole module (internal/uc):
brew install unicorn pkg-config
```

### Build

```bash
git clone https://github.com/clockiscool1234/golinux.git && cd golinux
go build -o golinux ./cmd/golinux
```

### Test

```bash
go test ./...          # unit tests (needs libunicorn for internal/uc's own tests)
go vet ./...           # two expected false-positive warnings in
                        # internal/uc about the cgo.Handle pattern —
                        # see the comment right above that line
gofmt -l .              # should print nothing
```

Some tests shell out to `musl-gcc` to compile tiny C programs on the
fly and run them through the full emulator end to end
(`internal/emulator/emulator_test.go`); they skip themselves cleanly
if `musl-gcc` isn't on `PATH`.

## Running

Every flag has a short, single-dash acronym form and a long,
double-dash descriptive form — use whichever you like:

| short | long                 | meaning                                          |
|-------|----------------------|---------------------------------------------------|
| `-r`  | `--vfs-root`         | host directory backing the guest `/`               |
| `-v`  | `--verbose`          | log every syscall to stderr                        |
| `-n`  | `--no-automount`     | skip the default proc/sysfs/devtmpfs mount         |
| `-X`  | `--extract-tarball`  | extract a tarball into the vfs root before running |
| `-e`  | `--env`              | extra env var `KEY=VAL` (repeatable)               |
| `-w`  | `--cwd`              | initial guest working directory                    |
| `-I`  | `--host-file`        | import a host file, `host:guest` (repeatable)      |

```bash
# Run a static binary, importing it into a fresh vfs root first:
./golinux --vfs-root ./vfsroot --host-file ./hello:/bin/hello /bin/hello arg1 arg2

# Log every syscall to stderr:
./golinux -r ./vfsroot -v /bin/hello

# Skip the default proc/sysfs/devtmpfs auto-mount:
./golinux --vfs-root ./vfsroot --no-automount /bin/hello

# Unpack a rootfs tarball into the vfs root, then run a binary from it:
./golinux -X alpine.tar.gz -r alpine /bin/sh
```

`--vfs-root` is reused across runs — files created, written, or
modified by the guest persist in that directory (with its
`.golinux_meta` sidecar files) between invocations, just like a real
disk would.

Run `./golinux -h` for the full flag list.

## Does this work on other operating systems?

**Building and running `golinux` itself currently requires Linux.**
Not because of anything fundamental about emulating a Linux guest —
it's because a handful of *host*-side syscalls used for real process-
group/session/job-control semantics (`internal/syscalls/process.go`),
for populating `native-perms` file stats (`internal/vfs/vfs.go`), and
for forwarding terminal `ioctl`s to the real host tty (`internal/
syscalls/ioctl.go`) call directly into Go's `syscall` package using
Linux-specific types and syscall numbers (`syscall.Stat_t`'s field
layout, a raw `syscall.SYS_GETSID` — Go's standard library doesn't wrap
`getsid` at all on any platform, so this port reaches for the raw
syscall number directly — and `syscall.SYS_IOCTL` with Linux `struct
termios`/`struct winsize` layouts). Neither of those compiles on macOS
or Windows as written.

`fork`/`vfork`/`clone`/`wait4` (see "Multi-process support" above) are
the one area that's already fully portable despite the general Linux-
only caveat above: the whole point of that design is that it never
calls the host's real `fork(2)` at all, so it carries no new platform
dependency — it's ordinary Go control flow (structs, goroutines,
channels) from top to bottom.

The good news for the rest is that this is a small, contained problem,
not an architectural one:

- **`internal/cpu`, the engine `internal/emulator` actually uses now,
  is pure Go with no cgo or C-toolchain dependency at all** — the
  original cgo binding to `libunicorn` (`internal/uc`) is no longer on
  the hot path, so there's no C-library cross-platform story to verify
  in the first place.
- **The VFS's sidecar-metadata design was chosen specifically to avoid
  relying on host filesystem permissions** (see "The virtual
  filesystem" above) — no `chown`/`chmod`/real symlinks means no
  platform-specific permission model to reconcile, which is normally
  the hardest part of porting this kind of tool.
- **The problem spots are narrow and already isolated** to
  `sysGetpgrp`/`sysGetpgid`/`sysSetpgid`/`sysGetsid`/`sysSetsid` in
  `process.go`, the `native_perms` branch of `vfs.Stat`/`vfs.GetMeta`
  in `vfs.go`, and `sysIoctl`'s real-syscall forwarding in `ioctl.go`.
  None is on the path any of the tests in this repo exercise (the
  default is `native_perms=false`, and job control/terminal ioctls
  only matter for interactive shell-style programs, not the batch/
  one-shot use case this CLI covers).

Making this genuinely cross-platform would mean splitting those spots
into `_linux.go`/`_darwin.go`/`_windows.go` files behind Go build tags,
each doing the platform-appropriate thing (or, on Windows, returning a
sensible stub since job-control groups and POSIX termios don't really
exist there).

Contributions doing that split are welcome — the boundaries are
already clean, it's just work nobody's done yet.

## Project layout

```
cmd/golinux/            CLI entrypoint
internal/
  elfload/               ELF64 parser (no dependencies)
  uc/                    cgo bindings to libunicorn (legacy CPU emulation
                         backend, kept as a drop-in alternative; no longer
                         imported by internal/emulator)
  vfs/                   host-backed virtual filesystem + sidecar metadata
  fds/                   file descriptor table (stdio, files, dirs, pipes)
  procfs/                synthetic /proc content
  devices/               /dev/null, /dev/zero, /dev/random, etc.
  cpu/                   pure-Go x86-64 CPU emulator core (including
                         SSE/AVX) -- the CPU emulation backend actually
                         used by internal/emulator today
  consts/                syscall numbers, flag bits (x86-64 Linux ABI)
  errno/                 errno values
  syscalls/              syscall handlers, one file per category:
    file.go               read/write/open/close/lseek/dup/fcntl/pipe
    ioctl.go                terminal ioctls (TCGETS/TIOCGWINSZ/etc.)
    fs_meta.go             stat/access/chmod/chown/readlink/umask
    dir.go                  getcwd/chdir/mkdir/rename/symlink/getdents64
    memory.go                brk/mmap/munmap/mprotect
    process.go                 getpid/getuid family/uname/sched_yield
    time.go                     gettimeofday/clock_gettime/getrandom
    arch.go                      arch_prctl/set_tid_address
    signal.go                     rt_sigaction et al. (stubs)
    mount.go                       mount/umount2/chroot/sethostname
    misc.go                         getrlimit/statfs/ftruncate
    fork.go                          execve, fork/vfork/clone, wait4
    exit.go                          exit/exit_group
  emulator/              wires everything together: ELF loading, the
                         cpu.Engine hooks, the run loop, and the fork/
                         wait4 child-process registry
```

Adding a new syscall means picking (or adding) the right category
file, writing the handler, and calling `register()` in that file's
`init()` — no shared table to merge-conflict over.

## The native Go CPU emulator

The actual x86-64 instruction execution is handled by `internal/cpu`,
a native, pure-Go x86-64 emulator: no cgo, no libunicorn, no C
toolchain required to build or run `golinux`.

This wasn't always the case — `internal/emulator` originally delegated
execution to Unicorn Engine (a C library) via a hand-written cgo
binding (`internal/uc`). `internal/cpu` was written from scratch to
replace it, matching `uc.Engine`'s exact method surface
(`MemMap`/`MemWrite`/`RegRead`/`HookInsn`/`EmuStart`/...) so the swap
was small and mechanical rather than a rewrite of `internal/emulator`:
paged memory, all GPRs/RIP/RFLAGS/FS_BASE/GS_BASE, a decoder/executor
covering the core integer instruction set (data movement, ADD/OR/ADC/
SBB/AND/SUB/XOR/CMP/TEST, INC/DEC/NOT/NEG, MUL/IMUL/DIV/IDIV, SHL/SHR/
SAR/ROL/ROR, JMP/CALL/RET/Jcc, SETcc/CMOVcc, LEA including RIP-relative
and SIB addressing, BT/BSF/BSR/POPCNT, XADD, BSWAP, CMPXCHG), string/
REP instructions (MOVS/STOS/LODS/CMPS/SCAS), the PREFETCHh/fence/
reserved-NOP family (`PREFETCHh`, `PREFETCHW`, `LFENCE`/`MFENCE`/
`SFENCE`, and the rest of the `0F 18`-`0F 1F` hint-opcode space — all
correctly no-ops, and `PREFETCHh` specifically never faults on a bad
address, matching real hardware), and core **SSE and AVX vector
instructions** (including XMM/YMM registers, VEX prefixes, data
movement — including `MOVNTPS`/`MOVNTPD` non-temporal stores — packed
integer/float arithmetic, and conversions). See the package doc
comment at the top of `internal/cpu/cpu.go` for exactly what's covered
and what isn't yet (no x87, no MMX, no far jumps/IN/OUT). It's
exercised by an extensive test suite in `internal/cpu/*_test.go` that
assemble real x86-64 via the host `as`/`objcopy` toolchain rather than
hand-encoded byte literals, so the test fixtures themselves are
trustworthy — including regression tests for real bugs found by
running genuine dynamically-linked binaries (a musl-linked shell and a
real Alpine `apk-tools` build) through the emulator end to end, such as
a ModRM decode bug that silently misread `%ah`/`%ch`/`%dh`/`%bh` as
`%spl`/`%bpl`/`%sil`/`%dil` whenever no REX prefix was present.

`internal/uc` still exists as a drop-in alternative backend, in case
`internal/cpu`'s current instruction coverage ever turns out to be
insufficient for some binary: swapping back (or running both side by
side behind a flag) means changing `internal/emulator`'s `engine
*cpu.Engine` field back to `*uc.Engine` and its `cpu.RegRAX`-style
constant references back to `uc.RegRAX`, not a rewrite.