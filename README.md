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
 │  emulator   │──install SYSCALL/CPUID hooks────────▶│  uc (cgo) │
 │  (Process)  │                                      │ Unicorn   │
 └──────┬──────┘◀─────────────────────────────────────┤  Engine   │
        │        every SYSCALL instruction traps here └───────────┘
        ▼
 ┌─────────────┐
 │  syscalls   │  ~60 syscall handlers, dispatched by number
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
   Unicorn CPU context (`internal/uc`, a small hand-written cgo
   binding to `libunicorn`), builds the initial stack (`argv`/`envp`/
   auxv, per the System V x86-64 ABI), and points `RIP` at the entry
   point.
3. `Process.Run()` calls `uc_emu_start`. Unicorn executes real machine
   code at full native speed until it hits a `syscall` or `cpuid`
   instruction, which trap into a Go callback via a cgo hook.
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
   fresh Unicorn context.

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

### Synthetic `/proc` and `/dev` (`internal/procfs`, `internal/devices`)

Once the guest `mount -t proc proc /proc`s (or the CLI auto-mounts it
at startup), reads under that mountpoint are generated on the fly from
live process state instead of touching disk — `/proc/version`,
`/proc/self/status`, `/proc/mounts`, etc. Device nodes under `/dev`
(`null`, `zero`, `full`, `random`/`urandom`, `tty`, `console`, `ptmx`)
are looked up by the (major, minor) numbers recorded on the node and
handled as in-memory pseudo-devices.

### What's implemented

~60 syscalls across file I/O, filesystem metadata, directory
operations, memory management (`brk`/`mmap`/`mprotect`), process/
identity introspection, time, and mount table management — see the
doc comment at the top of `internal/syscalls/syscalls.go` for the full
category breakdown and exactly what's stubbed vs. real.

**Deliberately not implemented yet**, each for a specific reason
documented in the corresponding file:

- **Real `fork`/`vfork`/`clone`/`wait4`** (`fork.go`) — Go's runtime
  isn't fork-safe the way CPython's is (see that file's long comment
  for why), so this needs a re-exec-based design rather than a direct
  port of the Python original's `os.fork()` call. `execve` *is*
  implemented (it's just an in-place image replacement, no host fork
  involved).
- **Real signal delivery** (`signal.go`) — `sigaction`/`sigprocmask`
  etc. report success so guest startup doesn't abort, but no sigtramp/
  context-switch machinery exists yet to actually invoke a registered
  handler.
- **`poll`/`select`/`ppoll`/`pselect6`** — need real multiplexed I/O
  across the fd table; reports `ENOSYS` rather than a fake stub that
  would make callers spin or hang confusingly.
- **Sockets** — not started.

## Building

### Requirements

- **Go 1.22+**
- **A C compiler** (cgo needs one) — `gcc` or `clang`
- **libunicorn 2.x**, headers and shared library (`pkg-config unicorn`
  must resolve)

On Debian/Ubuntu:

```bash
sudo apt-get install -y golang-go gcc pkg-config libunicorn-dev
```

On macOS (via Homebrew):

```bash
brew install go unicorn pkg-config
```

### Build

```bash
git clone <this repo> golinux && cd golinux
go build -o golinux ./cmd/golinux
```

### Test

```bash
go test ./...          # unit tests
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

```bash
# Run a static binary, importing it into a fresh vfs root first:
./golinux --vfs-root ./vfsroot --host-file ./hello:/bin/hello /bin/hello arg1 arg2

# Log every syscall to stderr:
./golinux --vfs-root ./vfsroot -v /bin/hello

# Skip the default proc/sysfs/devtmpfs auto-mount:
./golinux --vfs-root ./vfsroot --no-auto-mount /bin/hello
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
group/session/job-control semantics (`internal/syscalls/process.go`)
and for populating `native-perms` file stats (`internal/vfs/vfs.go`)
call directly into Go's `syscall` package using Linux-specific types
and syscall numbers (`syscall.Stat_t`'s field layout, and a raw
`syscall.SYS_GETSID` — Go's standard library doesn't wrap `getsid` at
all on any platform, so this port reaches for the raw syscall number
directly). Neither of those compiles on macOS or Windows as written.

The good news is that this is a small, contained problem, not an
architectural one:

- **Unicorn Engine itself is cross-platform** — Linux, macOS, and
  Windows are all officially supported, so `internal/uc`'s cgo binding
  has no OS-specific code in it at all.
- **The VFS's sidecar-metadata design was chosen specifically to avoid
  relying on host filesystem permissions** (see "The virtual
  filesystem" above) — no `chown`/`chmod`/real symlinks means no
  platform-specific permission model to reconcile, which is normally
  the hardest part of porting this kind of tool.
- **The two problem spots are narrow and already isolated** to
  `sysGetpgrp`/`sysGetpgid`/`sysSetpgid`/`sysGetsid`/`sysSetsid` in
  `process.go`, and the `native_perms` branch of `vfs.Stat`/
  `vfs.GetMeta` in `vfs.go`. Neither is on the path any of the tests
  in this repo exercise (the default is `native_perms=false`, and job
  control only matters for interactive shell-style programs, not the
  batch/one-shot use case this CLI covers).

Making this genuinely cross-platform would mean:

1. Splitting those two spots into `_linux.go`/`_darwin.go`/
   `_windows.go` files behind Go build tags, each doing the
   platform-appropriate thing (or, on Windows, returning a sensible
   stub since job-control groups don't really exist there).
2. Verifying `libunicorn`'s Windows build story (typically MSYS2/vcpkg)
   works smoothly with cgo's expectations there.

Contributions doing that split are welcome — the boundaries are
already clean, it's just work nobody's done yet.

## Project layout

```
cmd/golinux/            CLI entrypoint
internal/
  elfload/               ELF64 parser (no dependencies)
  uc/                    cgo bindings to libunicorn (the CPU emulation core)
  vfs/                   host-backed virtual filesystem + sidecar metadata
  fds/                   file descriptor table (stdio, files, dirs, pipes)
  procfs/                synthetic /proc content
  devices/               /dev/null, /dev/zero, /dev/random, etc.
  cpu/                   pure-Go x86-64 CPU emulator core (including SSE/AVX)
  consts/                syscall numbers, flag bits (x86-64 Linux ABI)
  errno/                 errno values
  syscalls/              syscall handlers, one file per category:
    file.go               read/write/open/close/lseek/dup/fcntl/pipe
    fs_meta.go             stat/access/chmod/chown/readlink/umask
    dir.go                  getcwd/chdir/mkdir/rename/symlink/getdents64
    memory.go                brk/mmap/munmap/mprotect
    process.go                 getpid/getuid family/uname/sched_yield
    time.go                     gettimeofday/clock_gettime/getrandom
    arch.go                      arch_prctl/set_tid_address
    signal.go                     rt_sigaction et al. (stubs)
    mount.go                       mount/umount2/chroot/sethostname
    misc.go                         getrlimit/statfs/ftruncate
    fork.go                          execve (real); fork/clone (not yet)
    exit.go                           exit/exit_group
  emulator/              wires everything together: ELF loading, the
                         Unicorn hooks, the run loop
```

Adding a new syscall means picking (or adding) the right category
file, writing the handler, and calling `register()` in that file's
`init()` — no shared table to merge-conflict over.

## Future direction: a native Go CPU emulator

Right now the actual x86-64 instruction execution is delegated
entirely to Unicorn Engine (a C library) via cgo. Writing a native,
pure-Go x86-64 emulator to replace it — full instruction decoding,
execution semantics, flags behavior, etc. — is a real possibility down
the line, since it would drop the cgo/C-toolchain dependency
entirely and make cross-compilation trivial.

**A first pass now exists** in `internal/cpu` (no cgo, no
libunicorn): paged memory, all GPRs/RIP/RFLAGS/FS_BASE/GS_BASE, and a
decoder/executor covering the core integer instruction set (data
movement, ADD/OR/ADC/SBB/AND/SUB/XOR/CMP/TEST, INC/DEC/NOT/NEG,
MUL/IMUL/DIV/IDIV, SHL/SHR/SAR/ROL/ROR, JMP/CALL/RET/Jcc, SETcc/
CMOVcc, LEA including RIP-relative and SIB addressing), as well as
core **SSE and AVX vector instructions** (including XMM/YMM registers, VEX
prefixes, data movement, packed integer/float arithmetic, and conversions).
See the package doc comment at the top of `internal/cpu/cpu.go` for exactly
what's covered and what isn't yet (no x87, no string/REP instructions).
It's exercised by an extensive test suite in `internal/cpu/*_test.go`
that assemble real x86-64 via the host `as`/`objcopy` toolchain rather
than hand-encoded byte literals, so the test fixtures themselves are
trustworthy.

It is not wired into `internal/emulator` yet — that's the next step,
and per the paragraph below it should be a small, mechanical one.

If that day comes, the seam is already clean: `internal/emulator` only
ever talks to `uc.Engine`'s small interface (`MemMap`/`MemWrite`/
`RegRead`/`HookInsn`/`EmuStart`/...). A pure-Go engine implementing
that same shape could drop in without touching `syscalls`, `vfs`,
`procfs`, or `devices` at all. `internal/cpu.Engine` already mirrors
that exact shape (same method names, same `Reg*`/`Ins*`/`Prot*`
constant names) for exactly this reason — swapping it in means
changing `internal/emulator`'s `engine *uc.Engine` field to
`*cpu.Engine` and its `uc.RegRAX`-style constant references to
`cpu.RegRAX`, not a rewrite.
