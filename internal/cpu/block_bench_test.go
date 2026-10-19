package cpu

import (
	"encoding/binary"
	"testing"
)

func BenchmarkInterpreterVsBasicBlock(b *testing.B) {
	shortLoop := []byte{
		0xb9, 0x40, 0x42, 0x0f, 0x00,
		0x31, 0xc0,
		0xff, 0xc0,
		0xff, 0xc9,
		0x75, 0xfa,
	}
	shortLoop = append(shortLoop, 0x0f, 0x05)
	longBlockLoop := []byte{0xb9, 0xa0, 0x86, 0x01, 0x00}
	for i := 0; i < 32; i++ {
		longBlockLoop = append(longBlockLoop, 0x05, 1, 0, 0, 0)
	}
	longBlockLoop = append(longBlockLoop, 0xff, 0xc9, 0x0f, 0x85, 0, 0, 0, 0)
	binary.LittleEndian.PutUint32(longBlockLoop[len(longBlockLoop)-4:], uint32(int32(5-len(longBlockLoop))))
	longBlockLoop = append(longBlockLoop, 0x0f, 0x05)

	for _, workload := range []struct {
		name string
		code []byte
	}{
		{name: "short-loop", code: shortLoop},
		{name: "long-block-loop", code: longBlockLoop},
	} {
		b.Run(workload.name, func(b *testing.B) {
			for _, test := range []struct {
				name string
				jit  bool
			}{
				{name: "interpreter"},
				{name: "basic-block", jit: true},
			} {
				b.Run(test.name, func(b *testing.B) {
					e, err := NewEngine()
					if err != nil {
						b.Fatal(err)
					}
					if err := e.MemMap(testCodeBase, pageSize, ProtRead|ProtExec); err != nil {
						b.Fatal(err)
					}
					if err := e.MemWrite(testCodeBase, workload.code); err != nil {
						b.Fatal(err)
					}
					if test.jit {
						e.SetBlockJIT(true)
					}
					if err := e.HookInsn(InsSyscall, func(e *Engine) {
						_ = e.EmuStop()
					}); err != nil {
						b.Fatal(err)
					}
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						if err := e.EmuStart(testCodeBase, 0); err != nil {
							b.Fatal(err)
						}
					}
				})
			}
		})
	}
}
