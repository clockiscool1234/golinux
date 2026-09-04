package cpu

import "fmt"

type operandKind int

const (
	opndReg operandKind = iota
	opndMem
	opndImm
)

// operand is a resolved instruction operand. For opndMem, addr is
// used directly unless ripRelative is set, in which case the real
// address is e.curInstrEnd + ripDisp -- resolved lazily because the
// displacement is known at ModRM-decode time but the instruction's
// end address (needed for RIP-relative addressing) isn't known until
// the whole instruction, including any trailing immediate, has been
// decoded. See decode.go's decodeOne for where curInstrEnd is set.
type operand struct {
	kind        operandKind
	reg         int // opndReg: register index 0-15
	rex         bool
	addr        uint64
	ripRelative bool
	ripDisp     int64
	imm         uint64 // opndImm: value, already sign/zero-extended into 64 bits as appropriate
}

func regOperand(reg int, rex bool) operand { return operand{kind: opndReg, reg: reg, rex: rex} }
func immOperand(v uint64) operand          { return operand{kind: opndImm, imm: v} }
func memOperand(addr uint64) operand       { return operand{kind: opndMem, addr: addr} }
func memOperandRIP(disp int64) operand {
	return operand{kind: opndMem, ripRelative: true, ripDisp: disp}
}

// effAddr resolves a memory operand's final address.
func (e *Engine) effAddr(o operand) uint64 {
	if o.ripRelative {
		return e.curInstrEnd + uint64(o.ripDisp)
	}
	return o.addr
}

func leToU64(b []byte) uint64 {
	var v uint64
	for i, x := range b {
		v |= uint64(x) << uint(8*i)
	}
	return v
}

func u64ToLE(v uint64, width int) []byte {
	b := make([]byte, width)
	for i := 0; i < width; i++ {
		b[i] = byte(v >> uint(8*i))
	}
	return b
}

// readOperand reads width bytes from o (a register, memory location,
// or immediate).
func (e *Engine) readOperand(o operand, width int) (uint64, error) {
	switch o.kind {
	case opndReg:
		return e.regs.readWidth(o.reg, width, o.rex), nil
	case opndImm:
		return o.imm, nil
	case opndMem:
		buf, err := e.mem.readChecked(e.effAddr(o), width, ProtRead)
		if err != nil {
			return 0, err
		}
		return leToU64(buf), nil
	}
	return 0, fmt.Errorf("cpu: readOperand: bad operand kind %d", o.kind)
}

// writeOperand writes val (truncated to width bytes) into o, which
// must be a register or memory operand.
func (e *Engine) writeOperand(o operand, width int, val uint64) error {
	switch o.kind {
	case opndReg:
		e.regs.writeWidth(o.reg, width, o.rex, val)
		return nil
	case opndMem:
		return e.mem.writeChecked(e.effAddr(o), u64ToLE(val, width), ProtWrite)
	}
	return fmt.Errorf("cpu: writeOperand: cannot write to operand kind %d", o.kind)
}

// leaAddr returns the address a memory operand refers to without
// dereferencing it -- what LEA needs.
func (e *Engine) leaAddr(o operand) (uint64, error) {
	if o.kind != opndMem {
		return 0, fmt.Errorf("cpu: LEA: operand is not memory")
	}
	return e.effAddr(o), nil
}

func signExtend(v uint64, fromBits int) uint64 {
	shift := 64 - fromBits
	return uint64(int64(v<<uint(shift)) >> uint(shift))
}
