package cpu

import (
	"math/rand"
	"testing"
)

func Test32BitFastFlagsMatchGenericArithmetic(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	pairs := [][2]uint32{
		{0, 0},
		{0, 1},
		{1, 0xffffffff},
		{0x7fffffff, 1},
		{0x80000000, 0xffffffff},
		{0xffffffff, 1},
		{0xf, 1},
		{0x10, 0xffffffff},
	}
	for i := 0; i < 10000; i++ {
		pairs = append(pairs, [2]uint32{rng.Uint32(), rng.Uint32()})
	}
	for _, pair := range pairs {
		initialFlags := rng.Uint64()
		generic, fast := &Engine{}, &Engine{}
		generic.regs.rflags, fast.regs.rflags = initialFlags, initialFlags
		want := uint32(generic.addWithFlags(uint64(pair[0]), uint64(pair[1]), 4))
		got := fast.add32Flags(pair[0], pair[1])
		if got != want || fast.regs.rflags != generic.regs.rflags {
			t.Fatalf("ADD32(%#x, %#x) = %#x flags=%#x; want %#x flags=%#x", pair[0], pair[1], got, fast.regs.rflags, want, generic.regs.rflags)
		}

		generic.regs.rflags, fast.regs.rflags = initialFlags, initialFlags
		want = uint32(generic.incFlags(uint64(pair[0]), 4))
		got = fast.inc32Flags(pair[0])
		if got != want || fast.regs.rflags != generic.regs.rflags {
			t.Fatalf("INC32(%#x) = %#x flags=%#x; want %#x flags=%#x", pair[0], got, fast.regs.rflags, want, generic.regs.rflags)
		}

		generic.regs.rflags, fast.regs.rflags = initialFlags, initialFlags
		want = uint32(generic.decFlags(uint64(pair[0]), 4))
		got = fast.dec32Flags(pair[0])
		if got != want || fast.regs.rflags != generic.regs.rflags {
			t.Fatalf("DEC32(%#x) = %#x flags=%#x; want %#x flags=%#x", pair[0], got, fast.regs.rflags, want, generic.regs.rflags)
		}
	}
}
