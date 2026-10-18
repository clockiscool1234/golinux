package cpu

import "testing"

func BenchmarkInterpreterVsBasicBlock(b *testing.B) {
	code := []byte{
		0xb9, 0x40, 0x42, 0x0f, 0x00,
		0x31, 0xc0,
		0xff, 0xc0,
		0xff, 0xc9,
		0x75, 0xfa,
	}
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
			if err := e.MemWrite(testCodeBase, code); err != nil {
				b.Fatal(err)
			}
			if test.jit {
				e.SetBlockJIT(true)
			}
			end := testCodeBase + uint64(len(code))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := e.EmuStart(testCodeBase, end); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
