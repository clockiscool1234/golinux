package cpu

import "fmt"

const (
	pageSize = 0x1000
	pageMask = pageSize - 1
)

// page is one 4KiB backing store plus its current protection bits.
type page struct {
	data [pageSize]byte
	perm int
}

// Memory is a sparse, page-granular guest address space. Pages are
// allocated lazily in a map rather than a flat 2^64 array; unmapped
// addresses simply have no entry.
type Memory struct {
	pages map[uint64]*page
}

func newMemory() *Memory {
	return &Memory{pages: make(map[uint64]*page)}
}

func pageAddr(addr uint64) uint64 { return addr &^ pageMask }

// faultError is returned by the permission-checked access path
// (fetchCheck) and carries what the caller needs to invoke
// HookMemUnmapped with the right MemType.
type faultError struct {
	MemType int
	Addr    uint64
	Size    int
}

func (f *faultError) Error() string {
	kind := map[int]string{MemReadUnmapped: "read", MemWriteUnmapped: "write", MemFetchUnmapped: "fetch"}[f.MemType]
	return fmt.Sprintf("unmapped %s at %#x (size %d)", kind, f.Addr, f.Size)
}

// MemMap maps a page-aligned, page-sized region with the given
// protection bits. Like uc_mem_map, it fails atomically (no partial
// mapping) if any page in the range is already mapped.
func (m *Memory) MemMap(addr, size uint64, perms int) error {
	if addr&pageMask != 0 || size == 0 || size&pageMask != 0 {
		return fmt.Errorf("cpu: MemMap: addr %#x / size %#x must be page-aligned and non-zero", addr, size)
	}
	for a := addr; a < addr+size; a += pageSize {
		if _, ok := m.pages[a]; ok {
			return fmt.Errorf("cpu: MemMap: %#x is already mapped", a)
		}
	}
	for a := addr; a < addr+size; a += pageSize {
		m.pages[a] = &page{perm: perms}
	}
	return nil
}

// MemUnmap removes the mapping covering [addr, addr+size). Pages in
// the range that aren't currently mapped are silently skipped rather
// than erroring -- callers in this codebase already discard MemUnmap
// errors for exactly this "unmap something possibly not mapped"
// reason (see the mmap/execImage paths in internal/emulator).
func (m *Memory) MemUnmap(addr, size uint64) error {
	base := pageAddr(addr)
	end := pageAddr(addr+size-1) + pageSize
	for a := base; a < end; a += pageSize {
		delete(m.pages, a)
	}
	return nil
}

// MemProtect updates the protection bits of every currently-mapped
// page in [addr, addr+size); pages not mapped are skipped (same
// leniency rationale as MemUnmap).
func (m *Memory) MemProtect(addr, size uint64, perms int) error {
	base := pageAddr(addr)
	end := pageAddr(addr+size-1) + pageSize
	for a := base; a < end; a += pageSize {
		if p, ok := m.pages[a]; ok {
			p.perm = perms
		}
	}
	return nil
}

// Clone returns a deep copy of m: every mapped page is duplicated
// (fresh backing array, same protection bits) so that writes through
// the clone never touch the original's pages or vice versa. Used by
// fork()/vfork() (see internal/emulator's doFork) to give a child
// process its own private copy of the parent's address space --
// real fork(2) gets this "for free" via copy-on-write page tables;
// this emulator has no host MMU to lean on, so it pays the full copy
// up front instead. That's the right tradeoff here: guest programs
// are typically small, and correctness (a genuinely independent
// address space, no risk of parent/child accidentally aliasing pages)
// matters far more than the copy's cost for this emulator's use case.
func (m *Memory) Clone() *Memory {
	out := &Memory{pages: make(map[uint64]*page, len(m.pages))}
	for addr, p := range m.pages {
		np := &page{perm: p.perm}
		np.data = p.data // [pageSize]byte is an array (value type): this copies the bytes
		out.pages[addr] = np
	}
	return out
}

// MemWrite/MemRead are the "direct host access" API: they bypass
// per-page protection bits (matching uc_mem_write/uc_mem_read, which
// let the emulator host poke guest memory the guest itself mapped
// read-only -- e.g. writing argv strings onto what will become a
// read-only stack guard page). They still fault on completely
// unmapped addresses.
func (m *Memory) MemWrite(addr uint64, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	return m.copy(addr, data, true, 0)
}

func (m *Memory) MemRead(addr uint64, size int) ([]byte, error) {
	if size == 0 {
		return nil, nil
	}
	buf := make([]byte, size)
	if err := m.copy(addr, buf, false, 0); err != nil {
		return nil, err
	}
	return buf, nil
}

// copy moves len(buf) bytes between guest memory at addr and buf.
// write selects direction; requirePerm, if non-zero, additionally
// requires every touched page to have that permission bit set
// (used by the fetch/exec path, never by the direct MemRead/MemWrite
// API above).
func (m *Memory) copy(addr uint64, buf []byte, write bool, requirePerm int) error {
	off := 0
	for off < len(buf) {
		pa := pageAddr(addr + uint64(off))
		p, ok := m.pages[pa]
		if !ok {
			mt := MemReadUnmapped
			if write {
				mt = MemWriteUnmapped
			}
			if requirePerm == ProtExec {
				mt = MemFetchUnmapped
			}
			return &faultError{MemType: mt, Addr: addr + uint64(off), Size: len(buf) - off}
		}
		if requirePerm != 0 && p.perm&requirePerm == 0 {
			mt := MemReadUnmapped
			if write {
				mt = MemWriteUnmapped
			}
			if requirePerm == ProtExec {
				mt = MemFetchUnmapped
			}
			return &faultError{MemType: mt, Addr: addr + uint64(off), Size: len(buf) - off}
		}
		pOff := (addr + uint64(off)) - pa
		var n int
		if write {
			n = copy(p.data[pOff:], buf[off:])
		} else {
			n = copy(buf[off:], p.data[pOff:])
		}
		off += n
	}
	return nil
}

// readChecked/writeChecked are used by the fetch/decode/execute path,
// which -- unlike the direct MemRead/MemWrite API -- must respect
// page protection: instruction fetch needs ProtExec, data reads need
// ProtRead, data writes need ProtWrite.
func (m *Memory) readChecked(addr uint64, size int, perm int) ([]byte, error) {
	buf := make([]byte, size)
	if err := m.copy(addr, buf, false, perm); err != nil {
		return nil, err
	}
	return buf, nil
}

func (m *Memory) writeChecked(addr uint64, data []byte, perm int) error {
	return m.copy(addr, data, true, perm)
}
