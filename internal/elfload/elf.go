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
