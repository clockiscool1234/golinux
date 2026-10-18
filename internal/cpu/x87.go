package cpu

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/bits"
)

type ext80 struct {
	significand  uint64
	signExponent uint16
}

func ext80FromFloat64Bits(value uint64) ext80 {
	sign := uint16(value>>48) & 0x8000
	exponent := (value >> 52) & 0x7ff
	fraction := value & ((uint64(1) << 52) - 1)

	switch exponent {
	case 0x7ff:
		significand := uint64(1) << 63
		if fraction != 0 {
			significand |= fraction << 11
			significand |= uint64(1) << 62
		}
		return ext80{significand: significand, signExponent: sign | 0x7fff}
	case 0:
		if fraction == 0 {
			return ext80{signExponent: sign}
		}
		shift := bits.LeadingZeros64(fraction) - 11
		return ext80{
			significand:  fraction << uint(shift+11),
			signExponent: sign | uint16(16383-1022-shift),
		}
	default:
		return ext80{
			significand:  (uint64(1)<<63 | fraction<<11),
			signExponent: sign | uint16(int(exponent)-1023+16383),
		}
	}
}

func ext80ToFloat64(value ext80) float64 {
	sign := uint64(value.signExponent&0x8000) << 48
	exponent := value.signExponent & 0x7fff
	if exponent == 0x7fff {
		if value.significand == uint64(1)<<63 {
			return math.Float64frombits(sign | uint64(0x7ff)<<52)
		}
		return math.Float64frombits(sign | uint64(0x7ff8)<<48 | (value.significand>>11)&((uint64(1)<<52)-1))
	}
	biasedExponent := int(exponent)
	if biasedExponent == 0 {
		biasedExponent = 1
	}
	v := math.Ldexp(float64(value.significand), biasedExponent-16383-63)
	return math.Float64frombits(math.Float64bits(v) | sign)
}

func (e *Engine) x87Load(o operand, width int) error {
	data, err := e.mem.readChecked(e.effAddr(o), width, ProtRead)
	if err != nil {
		return err
	}
	var value ext80
	switch width {
	case 4:
		value = ext80FromFloat64Bits(math.Float64bits(float64(math.Float32frombits(binary.LittleEndian.Uint32(data)))))
	case 8:
		value = ext80FromFloat64Bits(binary.LittleEndian.Uint64(data))
	case 10:
		value.significand = binary.LittleEndian.Uint64(data[:8])
		value.signExponent = binary.LittleEndian.Uint16(data[8:10])
	default:
		return fmt.Errorf("cpu: unsupported x87 load width %d", width)
	}
	e.regs.x87Top = (e.regs.x87Top + 7) & 7
	e.regs.x87[e.regs.x87Top] = value
	return nil
}

func (e *Engine) x87Store(o operand, width int, pop bool) error {
	value := e.regs.x87[e.regs.x87Top]
	var data []byte
	switch width {
	case 4:
		data = make([]byte, 4)
		binary.LittleEndian.PutUint32(data, math.Float32bits(float32(ext80ToFloat64(value))))
	case 8:
		data = make([]byte, 8)
		binary.LittleEndian.PutUint64(data, math.Float64bits(ext80ToFloat64(value)))
	case 10:
		data = make([]byte, 10)
		binary.LittleEndian.PutUint64(data[:8], value.significand)
		binary.LittleEndian.PutUint16(data[8:], value.signExponent)
	default:
		return fmt.Errorf("cpu: unsupported x87 store width %d", width)
	}
	if err := e.mem.writeChecked(e.effAddr(o), data, ProtWrite); err != nil {
		return err
	}
	if pop {
		e.regs.x87Top = (e.regs.x87Top + 1) & 7
	}
	return nil
}

func (e *Engine) x87Push(value ext80) {
	e.regs.x87Top = (e.regs.x87Top + 7) & 7
	e.regs.x87[e.regs.x87Top] = value
}

func (e *Engine) x87StoreRegister(index int, pop bool) {
	e.regs.x87[(e.regs.x87Top+uint8(index))&7] = e.regs.x87[e.regs.x87Top]
	if pop {
		e.regs.x87Top = (e.regs.x87Top + 1) & 7
	}
}

func (e *Engine) x87Add(index int) {
	top := e.regs.x87Top
	left := e.regs.x87[top]
	if index == 0 {
		exponent := left.signExponent & 0x7fff
		if exponent == 0x7fff || left.significand == 0 {
			return
		}
		if exponent == 0 {
			left.significand <<= 1
			if left.significand&(uint64(1)<<63) != 0 {
				exponent = 1
			}
			left.signExponent = left.signExponent&0x8000 | exponent
		} else if exponent == 0x7ffe {
			left.signExponent = left.signExponent&0x8000 | 0x7fff
			left.significand = uint64(1) << 63
		} else {
			left.signExponent++
		}
		e.regs.x87[top] = left
		return
	}
	other := e.regs.x87[(top+uint8(index))&7]
	a, b := ext80ToFloat64(left), ext80ToFloat64(other)
	e.regs.x87[top] = ext80FromFloat64Bits(math.Float64bits(a + b))
}

func (e *Engine) x87Compare(index int, pop bool) {
	a := e.regs.x87[e.regs.x87Top]
	b := e.regs.x87[(e.regs.x87Top+uint8(index))&7]
	aExp, bExp := a.signExponent&0x7fff, b.signExponent&0x7fff
	unordered := (aExp == 0x7fff && a.significand != uint64(1)<<63) || (bExp == 0x7fff && b.significand != uint64(1)<<63)
	less, equal := false, false
	if !unordered {
		av, bv := ext80ToFloat64(a), ext80ToFloat64(b)
		less, equal = av < bv, av == bv
	}
	e.setFlag(flagCF, unordered || less)
	e.setFlag(flagPF, unordered)
	e.setFlag(flagZF, unordered || equal)
	e.setFlag(flagAF, false)
	e.setFlag(flagSF, false)
	e.setFlag(flagOF, false)
	if pop {
		e.regs.x87Top = (e.regs.x87Top + 1) & 7
	}
}

func (e *Engine) x87Multiply32(o operand) error {
	data, err := e.mem.readChecked(e.effAddr(o), 4, ProtRead)
	if err != nil {
		return err
	}
	value := math.Float32frombits(binary.LittleEndian.Uint32(data))
	e.regs.x87[e.regs.x87Top] = ext80FromFloat64Bits(math.Float64bits(ext80ToFloat64(e.regs.x87[e.regs.x87Top]) * float64(value)))
	return nil
}

func (e *Engine) x87LoadControl(o operand) error {
	data, err := e.mem.readChecked(e.effAddr(o), 2, ProtRead)
	if err != nil {
		return err
	}
	e.regs.x87Control = binary.LittleEndian.Uint16(data)
	return nil
}

func (e *Engine) x87StoreControl(o operand) error {
	var data [2]byte
	binary.LittleEndian.PutUint16(data[:], e.regs.x87Control)
	return e.mem.writeChecked(e.effAddr(o), data[:], ProtWrite)
}

func (e *Engine) x87StoreInteger(o operand, width int, pop bool) error {
	value := ext80ToFloat64(e.regs.x87[e.regs.x87Top])
	switch (e.regs.x87Control >> 10) & 3 {
	case 0:
		value = math.RoundToEven(value)
	case 1:
		value = math.Floor(value)
	case 2:
		value = math.Ceil(value)
	case 3:
		value = math.Trunc(value)
	}
	bits := width * 8
	limit := math.Ldexp(1, bits-1)
	integer := uint64(1) << (bits - 1)
	if !math.IsNaN(value) && value >= -limit && value < limit {
		integer = uint64(int64(value))
	}
	var data [8]byte
	switch width {
	case 2:
		binary.LittleEndian.PutUint16(data[:2], uint16(integer))
	case 4:
		binary.LittleEndian.PutUint32(data[:4], uint32(integer))
	case 8:
		binary.LittleEndian.PutUint64(data[:], integer)
	default:
		return fmt.Errorf("cpu: unsupported x87 integer store width %d", width)
	}
	if err := e.mem.writeChecked(e.effAddr(o), data[:width], ProtWrite); err != nil {
		return err
	}
	if pop {
		e.regs.x87Top = (e.regs.x87Top + 1) & 7
	}
	return nil
}

func ext80FromInt64(value int64) ext80 {
	if value == 0 {
		return ext80{}
	}
	sign := uint16(0)
	magnitude := uint64(value)
	if value < 0 {
		sign = 0x8000
		magnitude = uint64(-(value + 1)) + 1
	}
	exponent := bits.Len64(magnitude) - 1
	return ext80{
		significand:  magnitude << uint(63-exponent),
		signExponent: sign | uint16(16383+exponent),
	}
}

func (e *Engine) x87LoadInteger(o operand, width int) error {
	data, err := e.mem.readChecked(e.effAddr(o), width, ProtRead)
	if err != nil {
		return err
	}
	var value int64
	switch width {
	case 2:
		value = int64(int16(binary.LittleEndian.Uint16(data)))
	case 4:
		value = int64(int32(binary.LittleEndian.Uint32(data)))
	case 8:
		value = int64(binary.LittleEndian.Uint64(data))
	default:
		return fmt.Errorf("cpu: unsupported x87 integer load width %d", width)
	}
	e.x87Push(ext80FromInt64(value))
	return nil
}

func (e *Engine) x87SubPop(index int) {
	top := e.regs.x87Top
	destination := (top + uint8(index)) & 7
	value := ext80ToFloat64(e.regs.x87[destination]) - ext80ToFloat64(e.regs.x87[top])
	e.regs.x87[destination] = ext80FromFloat64Bits(math.Float64bits(value))
	e.regs.x87Top = (top + 1) & 7
}
