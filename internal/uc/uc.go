// Package uc is a thin cgo wrapper around libunicorn's C API,
// providing just what the emulator package needs: memory mapping,
// register access, and hooks for the SYSCALL/CPUID instructions and
// unmapped-memory faults.
//
// This is deliberately hand-written and minimal rather than vendoring
// a full third-party Go binding, since the emulator only needs a small
// slice of Unicorn's API surface.
package uc

/*
#cgo pkg-config: unicorn
#include <stdlib.h>
#include <unicorn/unicorn.h>
#include <unicorn/x86.h>

// uc_hook_add is variadic in C, which cgo cannot call directly with a
// dynamic extra argument list. These fixed-arity wrappers pin down the
// exact hook signatures the emulator package uses.

static uc_err my_hook_add_insn(uc_engine *uc, uc_hook *hh, void *callback,
                                void *user_data, int insn_id) {
    return uc_hook_add(uc, hh, UC_HOOK_INSN, callback, user_data, (uint64_t)1, (uint64_t)0, insn_id);
}

static uc_err my_hook_add_mem_unmapped(uc_engine *uc, uc_hook *hh, void *callback,
                                        void *user_data) {
    return uc_hook_add(uc, hh, UC_HOOK_MEM_UNMAPPED, callback, user_data, (uint64_t)1, (uint64_t)0);
}

// Trampolines that cgo exports as real C functions matching the exact
// callback signatures libunicorn expects; see the //export directives
// on the corresponding Go functions below.
extern void goInsnHookTrampoline(uc_engine *uc, void *user_data);
extern bool goMemUnmappedHookTrampoline(uc_engine *uc, uc_mem_type type,
                                         uint64_t address, int size, int64_t value,
                                         void *user_data);
*/
import "C"

import (
	"errors"
	"runtime/cgo"
	"unsafe"
)

// Register IDs, re-exported as plain Go ints so callers don't need to
// import the C package themselves.
const (
	RegRAX    = int(C.UC_X86_REG_RAX)
	RegRBX    = int(C.UC_X86_REG_RBX)
	RegRCX    = int(C.UC_X86_REG_RCX)
	RegRDX    = int(C.UC_X86_REG_RDX)
	RegRSI    = int(C.UC_X86_REG_RSI)
	RegRDI    = int(C.UC_X86_REG_RDI)
	RegRBP    = int(C.UC_X86_REG_RBP)
	RegRSP    = int(C.UC_X86_REG_RSP)
	RegR8     = int(C.UC_X86_REG_R8)
	RegR9     = int(C.UC_X86_REG_R9)
	RegR10    = int(C.UC_X86_REG_R10)
	RegR11    = int(C.UC_X86_REG_R11)
	RegR12    = int(C.UC_X86_REG_R12)
	RegR13    = int(C.UC_X86_REG_R13)
	RegR14    = int(C.UC_X86_REG_R14)
	RegR15    = int(C.UC_X86_REG_R15)
	RegRIP    = int(C.UC_X86_REG_RIP)
	RegEFLAGS = int(C.UC_X86_REG_EFLAGS)
	RegFSBASE = int(C.UC_X86_REG_FS_BASE)
)

// Instruction IDs usable with HookInsn.
const (
	InsSyscall = int(C.UC_X86_INS_SYSCALL)
	InsCpuid   = int(C.UC_X86_INS_CPUID)
)

// Memory protection bits for MemMap / MemProtect.
const (
	ProtNone  = int(C.UC_PROT_NONE)
	ProtRead  = int(C.UC_PROT_READ)
	ProtWrite = int(C.UC_PROT_WRITE)
	ProtExec  = int(C.UC_PROT_EXEC)
	ProtAll   = int(C.UC_PROT_ALL)
)

// MemType values passed to MemUnmapped hooks.
const (
	MemReadUnmapped  = int(C.UC_MEM_READ_UNMAPPED)
	MemWriteUnmapped = int(C.UC_MEM_WRITE_UNMAPPED)
	MemFetchUnmapped = int(C.UC_MEM_FETCH_UNMAPPED)
)

// insnHookCtx is the value stored behind a cgo.Handle for an
// instruction hook: which Engine it belongs to and which Go callback
// to invoke.
type insnHookCtx struct {
	eng *Engine
	cb  func(*Engine)
}

// unmapHookCtx is the analogous context for the mem-unmapped hook.
type unmapHookCtx struct {
	eng *Engine
	cb  func(eng *Engine, memType int, addr uint64, size int) bool
}

// Engine wraps a single Unicorn CPU context (uc_engine*).
type Engine struct {
	uc      *C.uc_engine
	handles []cgo.Handle // kept alive for Close() to release
}

func ucErr(e C.uc_err) error {
	if e == C.UC_ERR_OK {
		return nil
	}
	return errors.New(C.GoString(C.uc_strerror(e)))
}

// NewEngine opens a fresh x86-64 Unicorn CPU context.
func NewEngine() (*Engine, error) {
	var raw *C.uc_engine
	if err := ucErr(C.uc_open(C.UC_ARCH_X86, C.UC_MODE_64, &raw)); err != nil {
		return nil, err
	}
	return &Engine{uc: raw}, nil
}

// Close releases the underlying Unicorn context and any hook handles.
func (e *Engine) Close() error {
	for _, h := range e.handles {
		h.Delete()
	}
	e.handles = nil
	if e.uc == nil {
		return nil
	}
	err := ucErr(C.uc_close(e.uc))
	e.uc = nil
	return err
}

// MemMap maps size bytes at addr with the given protection bits (see
// Prot* constants, OR'd together).
func (e *Engine) MemMap(addr, size uint64, perms int) error {
	return ucErr(C.uc_mem_map(e.uc, C.uint64_t(addr), C.size_t(size), C.uint32_t(perms)))
}

// MemUnmap unmaps a previously mapped region.
func (e *Engine) MemUnmap(addr, size uint64) error {
	return ucErr(C.uc_mem_unmap(e.uc, C.uint64_t(addr), C.size_t(size)))
}

// MemProtect changes the protection bits of an existing mapping.
func (e *Engine) MemProtect(addr, size uint64, perms int) error {
	return ucErr(C.uc_mem_protect(e.uc, C.uint64_t(addr), C.size_t(size), C.uint32_t(perms)))
}

// MemWrite writes data into guest memory at addr.
func (e *Engine) MemWrite(addr uint64, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	return ucErr(C.uc_mem_write(e.uc, C.uint64_t(addr), unsafe.Pointer(&data[0]), C.size_t(len(data))))
}

// MemRead reads size bytes of guest memory at addr.
func (e *Engine) MemRead(addr uint64, size int) ([]byte, error) {
	if size == 0 {
		return nil, nil
	}
	buf := make([]byte, size)
	if err := ucErr(C.uc_mem_read(e.uc, C.uint64_t(addr), unsafe.Pointer(&buf[0]), C.size_t(size))); err != nil {
		return nil, err
	}
	return buf, nil
}

// RegRead reads a 64-bit general purpose register.
func (e *Engine) RegRead(reg int) (uint64, error) {
	var val C.uint64_t
	if err := ucErr(C.uc_reg_read(e.uc, C.int(reg), unsafe.Pointer(&val))); err != nil {
		return 0, err
	}
	return uint64(val), nil
}

// RegWrite writes a 64-bit general purpose register.
func (e *Engine) RegWrite(reg int, val uint64) error {
	cval := C.uint64_t(val)
	return ucErr(C.uc_reg_write(e.uc, C.int(reg), unsafe.Pointer(&cval)))
}

// HookInsn registers cb to run whenever the given instruction ID
// (InsSyscall or InsCpuid) executes anywhere in the address space.
func (e *Engine) HookInsn(insnID int, cb func(*Engine)) error {
	h := cgo.NewHandle(&insnHookCtx{eng: e, cb: cb})
	e.handles = append(e.handles, h)
	var hh C.uc_hook
	// unsafe.Pointer(h): the documented cgo.Handle pattern for passing
	// an opaque Go value through C as a void* -- h is never
	// dereferenced on the C side, only round-tripped back into
	// cgo.Handle() in the trampoline below. `go vet` flags this
	// conversion pattern generically; it is safe here.
	return ucErr(C.my_hook_add_insn(e.uc, &hh, C.goInsnHookTrampoline,
		unsafe.Pointer(h), C.int(insnID)))
}

// HookMemUnmapped registers cb to run when the guest accesses
// unmapped memory. Returning true tells Unicorn to treat the access
// as satisfied (rare); false lets the fault propagate as an error
// from EmuStart.
func (e *Engine) HookMemUnmapped(cb func(eng *Engine, memType int, addr uint64, size int) bool) error {
	h := cgo.NewHandle(&unmapHookCtx{eng: e, cb: cb})
	e.handles = append(e.handles, h)
	var hh C.uc_hook
	return ucErr(C.my_hook_add_mem_unmapped(e.uc, &hh, C.goMemUnmappedHookTrampoline,
		unsafe.Pointer(h)))
}

// EmuStart begins emulation at begin, running until an explicit
// EmuStop(), a hook that stops it, or (if until != 0) execution
// reaching that address.
func (e *Engine) EmuStart(begin, until uint64) error {
	return ucErr(C.uc_emu_start(e.uc, C.uint64_t(begin), C.uint64_t(until), 0, 0))
}

// EmuStop halts emulation from within a hook callback.
func (e *Engine) EmuStop() error {
	return ucErr(C.uc_emu_stop(e.uc))
}

//export goInsnHookTrampoline
func goInsnHookTrampoline(ucPtr *C.uc_engine, userData unsafe.Pointer) {
	h := cgo.Handle(userData)
	ctx := h.Value().(*insnHookCtx)
	ctx.cb(ctx.eng)
}

//export goMemUnmappedHookTrampoline
func goMemUnmappedHookTrampoline(ucPtr *C.uc_engine, memType C.uc_mem_type, address C.uint64_t,
	size C.int, value C.int64_t, userData unsafe.Pointer) C.bool {
	h := cgo.Handle(userData)
	ctx := h.Value().(*unmapHookCtx)
	ok := ctx.cb(ctx.eng, int(memType), uint64(address), int(size))
	return C.bool(ok)
}
