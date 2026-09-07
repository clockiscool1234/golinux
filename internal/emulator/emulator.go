// Package emulator wires a CPU engine (internal/cpu, a native pure-Go
// x86-64 emulator -- see that package's doc comment for exactly what
// it supports) to an ELF image, a virtual filesystem, and the
// syscall table, and runs it to completion. Ported from
// sysemu/emulator.py.
//
// This package previously ran on Unicorn Engine via a cgo wrapper
// (internal/uc); that package still exists but is no longer imported
// here. internal/cpu was built specifically to be a drop-in
// replacement for it -- same MemMap/MemWrite/RegRead/HookInsn/
// EmuStart/... method surface, same Reg*/Ins*/Prot* constant names --
// so swapping back (or running both side by side behind a flag) is a
// small, mechanical change if internal/cpu's current instruction
// coverage ever turns out to be insufficient for some binary.
//
// Address space layout (chosen to loosely mirror a real x86_64 Linux
// process without needing ASLR):
//
//	0x0000000000400000   non-PIE (ET_EXEC) main image loads here
//	0x0000555555554000   PIE (ET_DYN) main image base, if PIE
//	0x0000600000000000   anonymous/file mmap() bump region
//	0x00007ffff7fc0000   dynamic linker (PT_INTERP) base, if present
//	0x00007ffffffde000   process stack (grows down from here)
//
// This covers ELF loading (including PT_INTERP dynamically-linked
// binaries, which get their own load bias and entry point), stack/
// auxv setup, and the syscalls in the internal/syscalls package.
package emulator

import (
	"encoding/binary"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golinux/internal/consts"
	"golinux/internal/cpu"
	"golinux/internal/elfload"
	"golinux/internal/errno"
	"golinux/internal/fds"
	"golinux/internal/syscalls"
	"golinux/internal/vfs"
)

const page = consts.PageSize

func pageAlignDown(x uint64) uint64 { return x &^ (page - 1) }
func pageAlignUp(x uint64) uint64   { return (x + page - 1) &^ (page - 1) }

func protToEngine(prot int) int {
	p := 0
	if prot&consts.PROT_READ != 0 {
		p |= cpu.ProtRead
	}
	if prot&consts.PROT_WRITE != 0 {
		p |= cpu.ProtWrite
	}
	if prot&consts.PROT_EXEC != 0 {
		p |= cpu.ProtExec
	}
	return p
}

const (
	mmapBase   = 0x600000000000
	mmapMax    = 0x6fffffff0000
	interpBase = 0x00007ffff7fc0000
	pieBase    = 0x0000555555554000
	stackTop   = 0x00007ffffffff000
	stackSize  = 8 * 1024 * 1024
)

// Process is one emulated guest process.
type Process struct {
	VFSRoot     *vfs.VFS
	ArgvVal     []string
	Envp        []string
	CwdVal      string
	Pid_        int
	PpidVal     int // 0 for the root process (no guest parent); set by doFork for children
	VerboseFlag bool
	LogFn       func(string)
	HostnameVal string
	BootTimeVal int64

	engine *cpu.Engine
	fds    *fds.Table

	mmapNext     uint64
	brkStart     uint64
	brkCur       uint64
	brkMappedEnd uint64
	fsbase       uint64
	umask        int

	uid, gid, euid, egid, suid, sgid, fsuid, fsgid uint32
	groups                                         []uint32

	entry    uint64
	exitCode *int

	cpuidPending   bool
	cpuidResumeRIP uint64

	pendingExec *syscalls.Execve
}

// NewProcess creates a process ready to Load() an ELF image.
func NewProcess(vv *vfs.VFS, argv, envp []string, cwd string, verbose bool) (*Process, error) {
	eng, err := cpu.NewEngine()
	if err != nil {
		return nil, err
	}
	if envp == nil {
		envp = []string{
			"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
			"HOME=/root", "TERM=xterm",
		}
	}
	p := &Process{
		VFSRoot: vv, ArgvVal: argv, Envp: envp, CwdVal: cwd,
		Pid_: os.Getpid(), VerboseFlag: verbose,
		HostnameVal: "golinux",
		BootTimeVal: time.Now().Unix(),
		umask:       0o022,
		engine:      eng,
		fds:         fds.NewTable(),
		mmapNext:    mmapBase,
	}
	return p, nil
}

// -- syscalls.Proc interface implementation --------------------------------

func (p *Process) MemRead(addr uint64, size int) ([]byte, error) { return p.engine.MemRead(addr, size) }
func (p *Process) MemWrite(addr uint64, data []byte) error       { return p.engine.MemWrite(addr, data) }
func (p *Process) Fds() *fds.Table                               { return p.fds }
func (p *Process) VFS() *vfs.VFS                                 { return p.VFSRoot }
func (p *Process) SetVFS(vv *vfs.VFS)                            { p.VFSRoot = vv }
func (p *Process) Pid() int                                      { return p.Pid_ }
func (p *Process) Ppid() int                                     { return p.PpidVal }
func (p *Process) Argv() []string                                { return p.ArgvVal }
func (p *Process) BootTime() int64                               { return p.BootTimeVal }
func (p *Process) Verbose() bool                                 { return p.VerboseFlag }

func (p *Process) Cwd() string       { return p.CwdVal }
func (p *Process) SetCwd(cwd string) { p.CwdVal = cwd }

func (p *Process) Umask() int { return p.umask }
func (p *Process) SetUmask(newMask int) int {
	old := p.umask
	p.umask = newMask & 0o777
	return old
}

func (p *Process) Hostname() string        { return p.HostnameVal }
func (p *Process) SetHostname(name string) { p.HostnameVal = name }

func (p *Process) Uid() uint32   { return p.uid }
func (p *Process) Gid() uint32   { return p.gid }
func (p *Process) Euid() uint32  { return p.euid }
func (p *Process) Egid() uint32  { return p.egid }
func (p *Process) Suid() uint32  { return p.suid }
func (p *Process) Sgid() uint32  { return p.sgid }
func (p *Process) Fsuid() uint32 { return p.fsuid }
func (p *Process) Fsgid() uint32 { return p.fsgid }

func (p *Process) SetUid(v uint32)   { p.uid = v }
func (p *Process) SetGid(v uint32)   { p.gid = v }
func (p *Process) SetEuid(v uint32)  { p.euid = v }
func (p *Process) SetEgid(v uint32)  { p.egid = v }
func (p *Process) SetSuid(v uint32)  { p.suid = v }
func (p *Process) SetSgid(v uint32)  { p.sgid = v }
func (p *Process) SetFsuid(v uint32) { p.fsuid = v }
func (p *Process) SetFsgid(v uint32) { p.fsgid = v }

func (p *Process) Groups() []uint32     { return p.groups }
func (p *Process) SetGroups(g []uint32) { p.groups = g }

func (p *Process) Log(msg string) {
	if !p.VerboseFlag {
		return
	}
	if p.LogFn != nil {
		p.LogFn(msg)
	} else {
		fmt.Fprintln(os.Stderr, msg)
	}
}

func (p *Process) SetFSBase(addr uint64) {
	p.fsbase = addr
	_ = p.engine.RegWrite(cpu.RegFSBASE, addr)
}
func (p *Process) GetFSBase() uint64 { return p.fsbase }

func (p *Process) DoBrk(addr uint64) uint64 {
	if addr == 0 || addr < p.brkStart {
		return p.brkCur
	}
	needEnd := pageAlignUp(addr)
	if needEnd > p.brkMappedEnd {
		size := needEnd - p.brkMappedEnd
		if err := p.engine.MemMap(p.brkMappedEnd, size, cpu.ProtAll); err != nil {
			p.Log(fmt.Sprintf("brk map failed: %v", err))
			return p.brkCur
		}
		p.brkMappedEnd = needEnd
	}
	p.brkCur = addr
	return p.brkCur
}

func (p *Process) DoMmap(addr, length uint64, prot, flags, fdNum int, offset uint64) (uint64, error) {
	length = pageAlignUp(length)
	// PROT_NONE (prot == 0, so protToEngine returns 0) is a real,
	// deliberate request -- e.g. musl's malloc mmaps a PROT_NONE
	// guard page (MAP_FIXED, right at the start of a freshly brk'd
	// heap region) specifically so writes past its bookkeeping
	// structures fault instead of silently corrupting adjacent
	// memory. There is no such thing as an "unspecified" prot to
	// fall back from here -- every caller passes an explicit value --
	// so perms is used exactly as translated, with no ProtAll
	// substitution.
	perms := protToEngine(prot)
	var base uint64
	if flags&consts.MAP_FIXED != 0 && addr != 0 {
		base = pageAlignDown(addr)
		_ = p.engine.MemUnmap(base, length)
		if err := p.engine.MemMap(base, length, perms); err != nil {
			return 0, err
		}
	} else {
		base = p.mmapNext
		newNext := p.mmapNext + length
		if newNext > mmapMax {
			return 0, fmt.Errorf("mmap arena exhausted")
		}
		if err := p.engine.MemMap(base, length, perms); err != nil {
			return 0, err
		}
		p.mmapNext = newNext
	}
	if flags&consts.MAP_ANONYMOUS == 0 {
		f := p.fds.Get(fdNum)
		if f != nil {
			data, err := readFileAt(f, int(length), offset)
			if err == nil {
				_ = p.engine.MemWrite(base, data)
			}
		}
	}
	return base, nil
}

// readFileAt reads up to n bytes at a fixed offset from a fds.File
// backed by a real *os.File (VFSFile), without disturbing its shared
// seek position. Non-seekable files (stdio, pipes) just aren't
// mmap-able in practice, so this is only meaningful for VFSFile.
func readFileAt(f fds.File, n int, offset uint64) ([]byte, error) {
	vf, ok := f.(*fds.VFSFile)
	if !ok {
		return nil, fmt.Errorf("not seekable")
	}
	return vf.PreadAt(n, int64(offset))
}

func (p *Process) DoMunmap(addr, length uint64) error {
	_ = p.engine.MemUnmap(pageAlignDown(addr), pageAlignUp(length))
	return nil
}

func (p *Process) DoMprotect(addr, length uint64, prot int) error {
	perms := protToEngine(prot)
	return p.engine.MemProtect(pageAlignDown(addr), pageAlignUp(length), perms)
}

// -- ELF loading -------------------------------------------------------

func (p *Process) mapSegments(img *elfload.Image, bias uint64) (uint64, error) {
	segs, err := elfload.LoadSegments(img)
	if err != nil {
		return 0, err
	}
	var top uint64
	for _, seg := range segs {
		base := pageAlignDown(seg.Vaddr + bias)
		end := pageAlignUp(seg.Vaddr + bias + seg.Memsz)
		size := end - base
		perms := protToEngine(
			boolMask(seg.Flags&elfload.PF_R != 0, consts.PROT_READ) |
				boolMask(seg.Flags&elfload.PF_W != 0, consts.PROT_WRITE) |
				boolMask(seg.Flags&elfload.PF_X != 0, consts.PROT_EXEC),
		)
		if perms == 0 {
			perms = cpu.ProtAll
		}
		_ = p.engine.MemMap(base, size, perms) // ignore "already mapped" overlap errors
		if err := p.engine.MemWrite(seg.Vaddr+bias, seg.Data); err != nil {
			return 0, fmt.Errorf("writing segment at %#x: %w", seg.Vaddr+bias, err)
		}
		if end > top {
			top = end
		}
	}
	return top, nil
}

// applyRelocations fixes up img's self-referencing pointers after
// mapSegments has written its (still link-time-relative) segment data
// into guest memory. Without this, any PIE/shared-object binary whose
// data section holds a pointer to itself or to another symbol within
// the same object (extremely common -- e.g. musl's combined
// libc+dynamic-linker relies on this for its own internal startup
// bookkeeping, not just for typical application code) ends up with
// that pointer still holding its raw link-time placeholder value
// instead of a real runtime address, and the first dereference of it
// walks off into unmapped memory.
//
// Only R_X86_64_RELATIVE is applied (bias + addend, no symbol lookup
// needed -- see that constant's doc comment in elfload for why this
// covers the common case). Other relocation types (R_X86_64_GLOB_DAT,
// R_X86_64_JUMP_SLOT, ...) need resolving a symbol against exported
// definitions across every loaded object, which this emulator doesn't
// do yet since so far nothing exercised has needed it; those entries
// are silently skipped rather than failing the whole load.
func (p *Process) applyRelocations(img *elfload.Image, bias uint64) error {
	relas, err := elfload.Relocations(img)
	if err != nil {
		return err
	}
	buf := make([]byte, 8)
	for _, r := range relas {
		if r.Type != elfload.R_X86_64_RELATIVE {
			continue
		}
		binary.LittleEndian.PutUint64(buf, bias+uint64(r.Addend))
		if err := p.engine.MemWrite(bias+r.Offset, buf); err != nil {
			return fmt.Errorf("applying relocation at %#x: %w", bias+r.Offset, err)
		}
	}
	return nil
}

func boolMask(b bool, v int) int {
	if b {
		return v
	}
	return 0
}

// phdrRuntimeAddr translates the program header table's file offset
// into the runtime address the guest will see at AT_PHDR. See the
// detailed comment in sysemu/emulator.py._phdr_runtime_addr for why
// this matters for non-PIE binaries.
func phdrRuntimeAddr(img *elfload.Image, bias uint64) uint64 {
	if img.IsPIE() {
		return bias + img.Phoff
	}
	for _, ph := range img.Segments {
		if ph.Type == elfload.PT_LOAD && ph.Offset <= img.Phoff && img.Phoff < ph.Offset+ph.Filesz {
			return (ph.Vaddr - ph.Offset) + img.Phoff + bias
		}
	}
	return img.Phoff + bias
}

// Load parses and maps path as this process's main image, sets up the
// stack/auxv, and installs the syscall/cpuid/mem-unmapped hooks.
func (p *Process) Load(path string) error {
	img, err := elfload.ParseFile(path)
	if err != nil {
		return err
	}
	bias := uint64(0)
	if img.IsPIE() {
		bias = pieBase
	}
	top, err := p.mapSegments(img, bias)
	if err != nil {
		return err
	}
	if err := p.applyRelocations(img, bias); err != nil {
		return err
	}
	p.brkStart, p.brkCur, p.brkMappedEnd = top, top, top

	entry := img.Entry + bias
	atBase := uint64(0)

	if img.Interp != "" {
		interpPath := img.Interp // symlink-following comes in a later pass
		if !p.VFSRoot.Exists(interpPath) {
			return fmt.Errorf(
				"dynamic interpreter %q not found in the VFS; populate the vfs root or "+
					"use a statically-linked binary (e.g. busybox-static)", interpPath)
		}
		hostInterp := p.VFSRoot.HostPath(interpPath)
		interpImg, err := elfload.ParseFile(hostInterp)
		if err != nil {
			return err
		}
		atBase = interpBase
		if _, err := p.mapSegments(interpImg, atBase); err != nil {
			return err
		}
		if err := p.applyRelocations(interpImg, atBase); err != nil {
			return err
		}
		entry = interpImg.Entry + atBase
	}

	if err := p.engine.MemMap(pageAlignDown(stackTop-stackSize), stackSize, cpu.ProtAll); err != nil {
		return err
	}

	auxv := map[int]uint64{
		consts.AT_PHDR:   phdrRuntimeAddr(img, bias),
		consts.AT_PHENT:  uint64(img.Phentsize),
		consts.AT_PHNUM:  uint64(img.Phnum),
		consts.AT_PAGESZ: page,
		consts.AT_BASE:   0,
		consts.AT_FLAGS:  0,
		consts.AT_ENTRY:  img.Entry + bias,
		consts.AT_UID:    0, consts.AT_EUID: 0, consts.AT_GID: 0, consts.AT_EGID: 0,
		consts.AT_HWCAP:  0,
		consts.AT_CLKTCK: 100,
		consts.AT_SECURE: 0,
	}
	if img.Interp != "" {
		auxv[consts.AT_BASE] = atBase
	}

	sp, err := p.setupStack(auxv, path)
	if err != nil {
		return err
	}

	_ = p.engine.RegWrite(cpu.RegRSP, sp)
	_ = p.engine.RegWrite(cpu.RegRIP, entry)
	if err := p.installHooks(); err != nil {
		return err
	}
	p.entry = entry
	return nil
}

// setupStack builds the initial stack image per the System V x86_64
// ABI:
//
//	[ argc ][ argv[0..n] ][ NULL ][ envp[0..m] ][ NULL ]
//	[ auxv pairs... ][ AT_NULL, 0 ]      <- rsp points here, 16-aligned
//	... padding ...
//	[ strings (argv/envp/execfn) ][ 16 random bytes ]  <- stackTop
func (p *Process) setupStack(auxv map[int]uint64, execfn string) (uint64, error) {
	top := uint64(stackTop)

	pushStr := func(s string) (uint64, error) {
		b := append([]byte(s), 0)
		top -= uint64(len(b))
		if err := p.engine.MemWrite(top, b); err != nil {
			return 0, err
		}
		return top, nil
	}

	argvPtrs := make([]uint64, len(p.ArgvVal))
	for i, a := range p.ArgvVal {
		ptr, err := pushStr(a)
		if err != nil {
			return 0, err
		}
		argvPtrs[i] = ptr
	}
	envpPtrs := make([]uint64, len(p.Envp))
	for i, e := range p.Envp {
		ptr, err := pushStr(e)
		if err != nil {
			return 0, err
		}
		envpPtrs[i] = ptr
	}
	execfnPtr, err := pushStr(execfn)
	if err != nil {
		return 0, err
	}

	top -= 16
	randomBytesAddr := top
	randBytes := make([]byte, 16)
	_, _ = readRandom(randBytes)
	if err := p.engine.MemWrite(randomBytesAddr, randBytes); err != nil {
		return 0, err
	}

	auxv[consts.AT_RANDOM] = randomBytesAddr
	auxv[consts.AT_EXECFN] = execfnPtr

	var words []uint64
	words = append(words, uint64(len(p.ArgvVal)))
	words = append(words, argvPtrs...)
	words = append(words, 0)
	words = append(words, envpPtrs...)
	words = append(words, 0)
	for k, v := range auxv {
		words = append(words, uint64(k), v)
	}
	words = append(words, consts.AT_NULL, 0)

	totalBytes := uint64(len(words) * 8)
	arrayStart := (top - totalBytes) &^ 0xF

	blob := make([]byte, len(words)*8)
	for i, w := range words {
		binary.LittleEndian.PutUint64(blob[i*8:i*8+8], w)
	}
	if err := p.engine.MemWrite(arrayStart, blob); err != nil {
		return 0, err
	}
	return arrayStart, nil
}

func readRandom(b []byte) (int, error) {
	f, err := os.Open("/dev/urandom")
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return f.Read(b)
}

// -- syscall / cpuid / unmapped-memory hooks -----------------------------

func (p *Process) installHooks() error {
	if err := p.engine.HookInsn(cpu.InsSyscall, p.onSyscall); err != nil {
		return err
	}
	if err := p.engine.HookInsn(cpu.InsCpuid, p.onCpuid); err != nil {
		return err
	}
	return p.engine.HookMemUnmapped(p.onMemUnmapped)
}

func (p *Process) onSyscall(e *cpu.Engine) {
	num, _ := e.RegRead(cpu.RegRAX)
	a0, _ := e.RegRead(cpu.RegRDI)
	a1, _ := e.RegRead(cpu.RegRSI)
	a2, _ := e.RegRead(cpu.RegRDX)
	a3, _ := e.RegRead(cpu.RegR10)
	a4, _ := e.RegRead(cpu.RegR8)
	a5, _ := e.RegRead(cpu.RegR9)
	rip, _ := e.RegRead(cpu.RegRIP)

	name, ok := consts.SyscallNames[int(num)]
	if !ok {
		name = fmt.Sprintf("%d", num)
	}

	ret, err := syscalls.Dispatch(p, int(num), a0, a1, a2, a3, a4, a5)
	if stop, isStop := err.(*syscalls.Stop); isStop {
		code := stop.Code
		p.exitCode = &code
		_ = e.EmuStop()
		return
	}
	if execve, isExecve := err.(*syscalls.Execve); isExecve {
		p.pendingExec = execve
		_ = e.EmuStop()
		return
	}
	if fork, isFork := err.(*syscalls.Fork); isFork {
		// e's RIP hasn't advanced past the 2-byte SYSCALL instruction
		// yet at this point (see cpu.Engine.HookInsn's doc comment),
		// so rip+2 is where both the parent (falling through below,
		// same as any other syscall) and the new child (about to
		// start running on its own goroutine) resume once fork()
		// "returns" -- 0 in the child, the child's pid in the parent.
		if childPid := p.doFork(fork.Vfork, rip+2); childPid < 0 {
			ret = int64(-errno.ENOMEM)
		} else {
			ret = int64(childPid)
		}
		// No EmuStop() here, unlike Stop/Execve above: the parent's
		// own engine was never touched by the fork, so it just
		// continues exactly like it would after any other syscall.
	}

	if p.VerboseFlag {
		if ret < 0 {
			p.Log(fmt.Sprintf("syscall %s(%#x,%#x,%#x,%#x) = %#x", name, a0, a1, a2, a3, ret))
		} else {
			p.Log(fmt.Sprintf("syscall %s(%#x,%#x,%#x,%#x) = %d", name, a0, a1, a2, a3, ret))
		}
	}
	_ = e.RegWrite(cpu.RegRAX, uint64(ret))
}

// onCpuid forces a conservative baseline-SSE2 feature set so ifunc
// resolvers never select AVX/AVX2/AVX-512/FMA/BMI code paths --
// Unicorn's TCG backend often reports those features via cpuid
// without fully supporting every encoding, which faults the instant
// the resolved function actually executes. See the corresponding
// comment in sysemu/emulator.py._on_cpuid for the full rationale.
func (p *Process) onCpuid(e *cpu.Engine) {
	leaf, _ := e.RegRead(cpu.RegRAX)
	leaf &= 0xFFFFFFFF
	var eax, ebx, ecx, edx uint64
	switch leaf {
	case 0:
		eax = 0x16
		ebx, edx, ecx = 0x756e6547, 0x49656e69, 0x6c65746e // "GenuineIntel"
	case 1:
		eax = 0x000306A9
		edx = 0x078BFBFF
		ecx = 0x00982201
	case 7:
		ebx, ecx, edx = 0, 0, 0
	case 0x80000000:
		eax = 0x80000004
	case 0x80000001:
		edx = (1 << 29) | (1 << 11)
		ecx = 1
	}
	rip, _ := e.RegRead(cpu.RegRIP)
	_ = e.RegWrite(cpu.RegRAX, eax)
	_ = e.RegWrite(cpu.RegRBX, ebx)
	_ = e.RegWrite(cpu.RegRCX, ecx)
	_ = e.RegWrite(cpu.RegRDX, edx)
	_ = e.RegWrite(cpu.RegRIP, rip+2)
	_ = e.EmuStop()
	p.cpuidResumeRIP = rip + 2
	p.cpuidPending = true
}

func (p *Process) onMemUnmapped(e *cpu.Engine, memType int, addr uint64, size int) bool {
	rip, _ := e.RegRead(cpu.RegRIP)
	p.Log(fmt.Sprintf("[unmapped memory access] addr=%#x size=%d at rip=%#x", addr, size, rip))
	return false
}

// execImage replaces the process's current image in place: a fresh
// cpu.Engine is opened (the old one is closed first -- engine
// contexts can't be "reset" short of closing and reopening), memory
// bookkeeping (mmap/brk/fsbase) is reset to a clean slate, and the
// new ELF is loaded exactly like the initial Load(). The fd table is
// deliberately left untouched, matching real execve(2) semantics:
// open files survive an exec (modulo O_CLOEXEC, which this port
// doesn't track per-fd yet).
func (p *Process) execImage(hostPath string, argv, envp []string) error {
	if err := p.engine.Close(); err != nil {
		p.Log(fmt.Sprintf("exec: closing previous engine: %v", err))
	}
	newEngine, err := cpu.NewEngine()
	if err != nil {
		return err
	}
	p.engine = newEngine
	p.mmapNext = mmapBase
	p.brkStart, p.brkCur, p.brkMappedEnd = 0, 0, 0
	p.fsbase = 0
	p.ArgvVal = argv
	if envp != nil {
		p.Envp = envp
	}
	return p.Load(hostPath)
}

// -- fork / wait4 -----------------------------------------------------------
//
// See internal/syscalls/fork.go's package doc comment for the full
// rationale (why this doesn't call the real fork(2), and what's
// simplified). In short: a "child" here is a full deep copy of the
// parent's CPU state and fd table, given a synthetic pid and run
// forward on its own goroutine -- never a real host process.
//
// childRecord/registry/childrenOf together are the minimal
// bookkeeping wait4() needs: given a parent pid, find its children
// (live or exited-but-unreaped, i.e. zombies) and block until one
// matching a requested pid exits. A flat, package-level registry
// (rather than something hung off each *Process) is enough because
// any process anywhere in the fork tree might have children, and
// wait4() only ever needs *this* process's own direct children.

// childRecord tracks one forked child from doFork until some wait4()
// call reaps it.
type childRecord struct {
	pid  int
	done chan struct{} // closed exactly once, right after the child's Run() returns

	// exitCode is only meaningful after done is closed; reaped is only
	// ever set (to true) by the one goroutine driving the parent that
	// owns this record, since only that goroutine ever calls Wait4 on
	// it -- but both are still guarded by registryMu because they're
	// also read by unrelated goroutines want to enumerate this
	// parent's children (there are none today, but future code -- a
	// /proc/<pid>/status "State: Z" line, say -- would want to).
	exitCode int
	reaped   bool
}

var (
	registryMu sync.Mutex
	childrenOf = map[int][]*childRecord{} // ppid -> that parent's children, live + unreaped zombies

	// nextChildPid counts up from childPidBase for every fork().
	// Guest pids handed to children are synthetic (see fork.go), so
	// this just needs to be unique within one run, not to resemble a
	// real pid_t sequence.
	nextChildPid = int64(childPidBase)
)

// childPidBase is chosen comfortably above any pid a real Linux
// system hands out by default (/proc/sys/kernel/pid_max is 4194304
// even at its largest configurable value) so synthetic child pids can
// never collide with the root process's real os.Getpid() (see
// NewProcess) within a single run.
const childPidBase = 1 << 23

func allocChildPid() int {
	return int(atomic.AddInt64(&nextChildPid, 1))
}

// doFork is what internal/syscalls.Fork actually triggers (see
// onSyscall): it deep-copies p into a new, independent *Process --
// its own cpu.Engine (registers + every mapped page) and its own
// fds.Table (new table, same underlying Files -- see fds.Table.Clone
// for why that's the correct shared-open-file-description behavior)
// -- assigns it a synthetic pid, and runs it forward on a new
// goroutine starting at resumeRIP. It returns the child's pid (for
// the parent's RAX), or -1 if the child engine's hooks failed to
// install (fork() reporting ENOMEM to the guest, same as a real
// kernel out of resources -- this codepath doesn't actually allocate
// host memory beyond the copies already made, but there's no more
// specific real-world errno for "internal setup failed").
func (p *Process) doFork(vfork bool, resumeRIP uint64) int {
	child := &Process{
		VFSRoot:     p.VFSRoot, // shared: fork() shares the parent's mount namespace
		ArgvVal:     append([]string(nil), p.ArgvVal...),
		Envp:        append([]string(nil), p.Envp...),
		CwdVal:      p.CwdVal,
		Pid_:        allocChildPid(),
		PpidVal:     p.Pid_,
		VerboseFlag: p.VerboseFlag,
		LogFn:       p.LogFn,
		HostnameVal: p.HostnameVal,
		BootTimeVal: p.BootTimeVal,

		engine: p.engine.Clone(),
		fds:    p.fds.Clone(),

		mmapNext:     p.mmapNext,
		brkStart:     p.brkStart,
		brkCur:       p.brkCur,
		brkMappedEnd: p.brkMappedEnd,
		fsbase:       p.fsbase,
		umask:        p.umask,

		uid: p.uid, gid: p.gid, euid: p.euid, egid: p.egid,
		suid: p.suid, sgid: p.sgid, fsuid: p.fsuid, fsgid: p.fsgid,
		groups: append([]uint32(nil), p.groups...),

		entry: resumeRIP,
	}
	if err := child.installHooks(); err != nil {
		p.Log(fmt.Sprintf("[fork] installing hooks on child engine: %v", err))
		return -1
	}
	// fork() returns 0 in the child -- the parent's own RAX is set by
	// onSyscall, from this function's return value.
	_ = child.engine.RegWrite(cpu.RegRAX, 0)

	rec := &childRecord{pid: child.Pid_, done: make(chan struct{})}
	registryMu.Lock()
	childrenOf[p.Pid_] = append(childrenOf[p.Pid_], rec)
	registryMu.Unlock()

	kind := "fork"
	if vfork {
		kind = "vfork"
	}
	p.Log(fmt.Sprintf("[%s] spawned child pid %d", kind, child.Pid_))

	go func() {
		code, runErr := child.Run()
		if runErr != nil {
			child.Log(fmt.Sprintf("[%s] child exited abnormally: %v", kind, runErr))
			code = 128
		}
		registryMu.Lock()
		rec.exitCode = code
		registryMu.Unlock()
		close(rec.done)
	}()

	return child.Pid_
}

// Wait4 implements wait4(2) against p's own forked children. It
// blocks the calling goroutine when no matching child has exited yet
// (unless WNOHANG is set) -- which is exactly right here: that
// goroutine IS this guest process's only thread of execution, so
// parking it until a child changes state is precisely what a real,
// single-threaded wait4() call does to its one and only thread.
//
// pid follows wait4(2)'s convention (< -1: process group, -1: any
// child, 0: any child in the caller's process group, > 0: that
// specific child) except that this port doesn't model guest process
// groups, so 0 and negative-but-not-(-1) values are treated the same
// as -1 ("any child") -- a safe, documented simplification, since no
// guest program this emulator targets relies on process-group-scoped
// waiting.
func (p *Process) Wait4(pid int64, wstatusPtr uint64, options int) (int64, error) {
	const wnohang = 1

	any := pid <= 0
	matches := func(r *childRecord) bool { return !r.reaped && (any || int64(r.pid) == pid) }

	registryMu.Lock()
	var candidates []*childRecord
	for _, r := range childrenOf[p.Pid_] {
		if matches(r) {
			candidates = append(candidates, r)
		}
	}
	registryMu.Unlock()

	if len(candidates) == 0 {
		return int64(-errno.ECHILD), nil
	}

	var rec *childRecord
	for _, r := range candidates {
		select {
		case <-r.done:
			rec = r
		default:
		}
		if rec != nil {
			break
		}
	}

	if rec == nil {
		if options&wnohang != 0 {
			return 0, nil
		}
		rec = waitAnyChild(candidates)
	}

	registryMu.Lock()
	rec.reaped = true
	exitCode, childPid := rec.exitCode, rec.pid
	registryMu.Unlock()

	if wstatusPtr != 0 {
		// Bits 8-15 hold the exit status for a normally-exited child
		// (WIFEXITED true iff the low byte is 0, WEXITSTATUS reads
		// bits 8-15) -- exit()/exit_group() already mask their code
		// to a byte (see exit.go), so this matches real wait(2)
		// encoding exactly for every code this emulator can produce.
		status := uint32(exitCode&0xff) << 8
		buf := make([]byte, 4)
		binary.LittleEndian.PutUint32(buf, status)
		_ = p.MemWrite(wstatusPtr, buf)
	}
	return int64(childPid), nil
}

// waitAnyChild blocks until at least one of recs is done and returns
// it. For the common single-candidate case (a specific-pid wait, or
// an only child) it just waits on that one channel directly; for
// several candidates (a "wait for any child" call with more than one
// live child) it fans their done channels into one via a short-lived
// helper goroutine per candidate, each of which exits the instant its
// channel closes.
func waitAnyChild(recs []*childRecord) *childRecord {
	if len(recs) == 1 {
		<-recs[0].done
		return recs[0]
	}
	winner := make(chan *childRecord, len(recs))
	for _, r := range recs {
		r := r
		go func() {
			<-r.done
			select {
			case winner <- r:
			default:
			}
		}()
	}
	return <-winner
}

// -- run ------------------------------------------------------------------

// cpuidPending/cpuidResumeRIP (on Process) let Run() re-enter
// emu_start after a cpuid trap without re-triggering the same hook at
// the same instruction (Unicorn's INSN hooks fire *before* the
// instruction executes and can't "skip" it from inside the callback
// the way the Python version's outer run() loop does).

// Run executes the loaded image until it exits, returning its exit
// code.
func (p *Process) Run() (int, error) {
	for {
		p.exitCode = nil
		p.cpuidPending = false
		p.pendingExec = nil
		err := p.engine.EmuStart(p.entry, 0)
		if err != nil && p.exitCode == nil && !p.cpuidPending && p.pendingExec == nil {
			return 0, fmt.Errorf("emulation halted unexpectedly: %w", err)
		}
		if p.exitCode != nil {
			return *p.exitCode, nil
		}
		if p.cpuidPending {
			p.entry = p.cpuidResumeRIP
			continue
		}
		if p.pendingExec != nil {
			exec := p.pendingExec
			hostPath := p.VFSRoot.HostPath(exec.Path)
			if err := p.execImage(hostPath, exec.Argv, exec.Envp); err != nil {
				return 0, fmt.Errorf("execve %s: %w", exec.Path, err)
			}
			continue
		}
		return 0, nil
	}
}
