// Package elfload is a minimal ELF64 little-endian parser for x86_64
// executables, ported from sysemu/elf.py.
//
// Deliberately dependency-free so it can be unit tested without any
// other subsystem. Only reads what's needed to load a program: the ELF
// header and PT_LOAD / PT_INTERP / PT_PHDR segments.
package elfload

import (
	"encoding/binary"
	"errors"
	"os"
)

const (
	ELFCLASS64  = 2
	ELFDATA2LSB = 1
	ET_EXEC     = 2
	ET_DYN      = 3

	PT_NULL    = 0
	PT_LOAD    = 1
	PT_DYNAMIC = 2
	PT_INTERP  = 3
	PT_PHDR    = 6

	PF_X = 1
	PF_W = 2
	PF_R = 4

	// -- .dynamic tags (Elf64_Dyn.d_tag) needed to locate the
	// relocation tables -- just enough to find DT_RELA/DT_JMPREL, not
	// a general-purpose dynamic-section parser.
	DT_NULL     = 0
	DT_PLTRELSZ = 2
	DT_PLTREL   = 20
	DT_JMPREL   = 23
	DT_RELA     = 7
	DT_RELASZ   = 8
	DT_RELAENT  = 9

	// R_X86_64_RELATIVE is the one relocation type that needs no
	// symbol resolution at all -- just "load base + addend" -- which
	// makes it both the simplest to implement and, in practice, the
	// overwhelming majority of what a single self-contained shared
	// object (like musl's combined libc+dynamic-linker) actually
	// needs to fix up its own internal self-pointers at load time.
	R_X86_64_RELATIVE = 8
)

// ELFError is a parse failure, mirroring Python's ELFError.
type ELFError struct{ Msg string }

func (e *ELFError) Error() string { return e.Msg }

// ProgramHeader is one entry of the program header table.
type ProgramHeader struct {
	Type   uint32
	Flags  uint32
	Offset uint64
	Vaddr  uint64
	Paddr  uint64
	Filesz uint64
	Memsz  uint64
	Align  uint64
}

// Image is a parsed ELF64 executable.
type Image struct {
	Path      string
	Data      []byte
	Type      uint16
	Entry     uint64
	Phoff     uint64
	Phentsize uint16
	Phnum     uint16
	Segments  []ProgramHeader
	Interp    string // "" if none
}

// IsPIE reports whether the image is position-independent (ET_DYN).
func (img *Image) IsPIE() bool { return img.Type == ET_DYN }

const ehdrSize = 64 // sizeof Elf64_Ehdr
const phdrSize = 56 // sizeof Elf64_Phdr

// ParseFile reads and parses an ELF file from disk.
func ParseFile(path string) (*Image, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseBytes(data, path)
}

// ParseBytes parses an in-memory ELF64 image. path is used only for
// error messages.
func ParseBytes(data []byte, path string) (*Image, error) {
	if path == "" {
		path = "<mem>"
	}
	if len(data) < ehdrSize || string(data[:4]) != "\x7fELF" {
		return nil, &ELFError{Msg: path + ": not an ELF file"}
	}

	ident := data[:16]
	if ident[4] != ELFCLASS64 {
		return nil, &ELFError{Msg: path + ": only 64-bit ELF is supported"}
	}
	if ident[5] != ELFDATA2LSB {
		return nil, &ELFError{Msg: path + ": only little-endian ELF is supported"}
	}

	eType := binary.LittleEndian.Uint16(data[16:18])
	eMachine := binary.LittleEndian.Uint16(data[18:20])
	// eVersion := binary.LittleEndian.Uint32(data[20:24])
	eEntry := binary.LittleEndian.Uint64(data[24:32])
	ePhoff := binary.LittleEndian.Uint64(data[32:40])
	// eShoff := binary.LittleEndian.Uint64(data[40:48])
	// eFlags := binary.LittleEndian.Uint32(data[48:52])
	// eEhsize := binary.LittleEndian.Uint16(data[52:54])
	ePhentsize := binary.LittleEndian.Uint16(data[54:56])
	ePhnum := binary.LittleEndian.Uint16(data[56:58])

	if eMachine != 0x3E {
		return nil, &ELFError{Msg: path + ": only x86_64 (EM_X86_64) is supported"}
	}

	img := &Image{
		Path: path, Data: data, Type: eType, Entry: eEntry,
		Phoff: ePhoff, Phentsize: ePhentsize, Phnum: ePhnum,
	}

	for i := 0; i < int(ePhnum); i++ {
		off := int(ePhoff) + i*int(ePhentsize)
		if off+phdrSize > len(data) {
			return nil, &ELFError{Msg: path + ": truncated program header table"}
		}
		phData := data[off : off+phdrSize]
		ph := ProgramHeader{
			Type:   binary.LittleEndian.Uint32(phData[0:4]),
			Flags:  binary.LittleEndian.Uint32(phData[4:8]),
			Offset: binary.LittleEndian.Uint64(phData[8:16]),
			Vaddr:  binary.LittleEndian.Uint64(phData[16:24]),
			Paddr:  binary.LittleEndian.Uint64(phData[24:32]),
			Filesz: binary.LittleEndian.Uint64(phData[32:40]),
			Memsz:  binary.LittleEndian.Uint64(phData[40:48]),
			Align:  binary.LittleEndian.Uint64(phData[48:56]),
		}
		img.Segments = append(img.Segments, ph)
		if ph.Type == PT_INTERP {
			end := ph.Offset + ph.Filesz
			if end > uint64(len(data)) {
				return nil, &ELFError{Msg: path + ": PT_INTERP out of range"}
			}
			raw := data[ph.Offset:end]
			if idx := indexByte(raw, 0); idx >= 0 {
				raw = raw[:idx]
			}
			img.Interp = string(raw)
		}
	}

	return img, nil
}

func indexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}

// Segment is one PT_LOAD segment ready to map: file data already
// zero-padded/truncated to Memsz (BSS handling).
type Segment struct {
	Vaddr uint64
	Memsz uint64
	Data  []byte
	Flags uint32
}

// LoadSegments returns every PT_LOAD segment of img.
func LoadSegments(img *Image) ([]Segment, error) {
	var out []Segment
	for _, ph := range img.Segments {
		if ph.Type != PT_LOAD {
			continue
		}
		end := ph.Offset + ph.Filesz
		if end > uint64(len(img.Data)) {
			return nil, errors.New("PT_LOAD segment out of range")
		}
		segData := make([]byte, ph.Memsz)
		copy(segData, img.Data[ph.Offset:end])
		out = append(out, Segment{Vaddr: ph.Vaddr, Memsz: ph.Memsz, Data: segData, Flags: ph.Flags})
	}
	return out, nil
}

// Rela is one parsed Elf64_Rela entry: the fields needed to apply
// R_X86_64_RELATIVE (Type is checked by the caller; Sym is kept for
// future symbol-based relocation types but unused for RELATIVE).
type Rela struct {
	Offset uint64
	Type   uint32
	Sym    uint32
	Addend int64
}

// vaddrToFileOffset finds the PT_LOAD segment covering vaddr and
// returns the corresponding offset into img.Data. Relocation tables
// are always themselves part of some PT_LOAD segment (the dynamic
// linker has to be able to read them without any special-case
// mapping), so this is enough to locate them without needing a
// separate "read raw bytes at this vaddr" path.
func vaddrToFileOffset(img *Image, vaddr uint64) (uint64, bool) {
	for _, ph := range img.Segments {
		if ph.Type != PT_LOAD {
			continue
		}
		if vaddr >= ph.Vaddr && vaddr < ph.Vaddr+ph.Filesz {
			return ph.Offset + (vaddr - ph.Vaddr), true
		}
	}
	return 0, false
}

// dynEntry is one raw Elf64_Dyn tag/value pair.
type dynEntry struct {
	Tag int64
	Val uint64
}

// parseDynamic reads the PT_DYNAMIC segment's tag/value array. Returns
// nil (not an error) if img has no PT_DYNAMIC segment -- static
// binaries and, in principle, some contrived shared objects legitimately
// have none.
func parseDynamic(img *Image) ([]dynEntry, error) {
	var dyn *ProgramHeader
	for i := range img.Segments {
		if img.Segments[i].Type == PT_DYNAMIC {
			dyn = &img.Segments[i]
			break
		}
	}
	if dyn == nil {
		return nil, nil
	}
	const dynEntSize = 16 // sizeof Elf64_Dyn: int64 d_tag + uint64 d_val/d_ptr
	end := dyn.Offset + dyn.Filesz
	if end > uint64(len(img.Data)) {
		return nil, &ELFError{Msg: img.Path + ": PT_DYNAMIC out of range"}
	}
	var out []dynEntry
	for off := dyn.Offset; off+dynEntSize <= end; off += dynEntSize {
		tag := int64(binary.LittleEndian.Uint64(img.Data[off : off+8]))
		val := binary.LittleEndian.Uint64(img.Data[off+8 : off+16])
		if tag == DT_NULL {
			break
		}
		out = append(out, dynEntry{Tag: tag, Val: val})
	}
	return out, nil
}

// readRelaTable parses a single Elf64_Rela array (used for both
// DT_RELA/.rela.dyn and DT_JMPREL/.rela.plt, which share the same
// entry layout) located at vaddr, sizeBytes long.
func readRelaTable(img *Image, vaddr, sizeBytes uint64) ([]Rela, error) {
	if sizeBytes == 0 {
		return nil, nil
	}
	fileOff, ok := vaddrToFileOffset(img, vaddr)
	if !ok {
		return nil, &ELFError{Msg: img.Path + ": relocation table vaddr not backed by any PT_LOAD segment"}
	}
	const relaEntSize = 24 // sizeof Elf64_Rela: r_offset, r_info (both u64), r_addend (s64)
	end := fileOff + sizeBytes
	if end > uint64(len(img.Data)) {
		return nil, &ELFError{Msg: img.Path + ": relocation table out of range"}
	}
	var out []Rela
	for off := fileOff; off+relaEntSize <= end; off += relaEntSize {
		rOffset := binary.LittleEndian.Uint64(img.Data[off : off+8])
		rInfo := binary.LittleEndian.Uint64(img.Data[off+8 : off+16])
		rAddend := int64(binary.LittleEndian.Uint64(img.Data[off+16 : off+24]))
		out = append(out, Rela{
			Offset: rOffset,
			Type:   uint32(rInfo),
			Sym:    uint32(rInfo >> 32),
			Addend: rAddend,
		})
	}
	return out, nil
}

// Relocations returns every relocation entry from both .rela.dyn
// (DT_RELA) and .rela.plt (DT_JMPREL, only when DT_PLTREL says it's
// RELA-format, which is what x86_64 always uses) in img's PT_DYNAMIC
// segment. Callers apply whichever entry types they support (today,
// just R_X86_64_RELATIVE -- see the constant's doc comment) and are
// expected to silently skip the rest rather than fail the whole load,
// since symbol-based types need cross-object symbol resolution this
// package doesn't do yet.
func Relocations(img *Image) ([]Rela, error) {
	entries, err := parseDynamic(img)
	if err != nil || entries == nil {
		return nil, err
	}

	var relaVaddr, relaSize uint64
	var jmprelVaddr, pltrelsz uint64
	var pltrelIsRela bool
	for _, e := range entries {
		switch e.Tag {
		case DT_RELA:
			relaVaddr = e.Val
		case DT_RELASZ:
			relaSize = e.Val
		case DT_JMPREL:
			jmprelVaddr = e.Val
		case DT_PLTRELSZ:
			pltrelsz = e.Val
		case DT_PLTREL:
			pltrelIsRela = e.Val == DT_RELA
		}
	}

	var out []Rela
	if relaVaddr != 0 && relaSize != 0 {
		rs, err := readRelaTable(img, relaVaddr, relaSize)
		if err != nil {
			return nil, err
		}
		out = append(out, rs...)
	}
	if jmprelVaddr != 0 && pltrelsz != 0 && pltrelIsRela {
		rs, err := readRelaTable(img, jmprelVaddr, pltrelsz)
		if err != nil {
			return nil, err
		}
		out = append(out, rs...)
	}
	return out, nil
}
