package cpu

const (
	maxBlockInstructions = 32
	blockCacheSize       = 1024
)

type basicBlock struct {
	start        uint64
	generation   uint64
	instructions []*decoded
}

func (e *Engine) cachedDecode(pc uint64) (*decoded, error) {
	pageAddr := pc &^ uint64(pageMask)
	page := e.cachedDecodePage
	if page == nil || e.cachedDecodePageAddr != pageAddr {
		page = e.decodeCache[pageAddr]
		if page == nil {
			page = &decodedPage{}
			e.decodeCache[pageAddr] = page
		}
		e.cachedDecodePageAddr = pageAddr
		e.cachedDecodePage = page
	}
	idx := pc & uint64(pageMask)
	if d := page.entries[idx]; d != nil {
		return d, nil
	}
	d, err := e.decodeOne(pc)
	if err != nil {
		return nil, err
	}
	page.entries[idx] = d
	return d, nil
}

func (e *Engine) compileBlock(start uint64) (*basicBlock, error) {
	if e.cachedBlock != nil && e.cachedBlockStart == start && e.cachedBlock.generation == e.blockCacheGeneration {
		return e.cachedBlock, nil
	}
	slot := int((start >> 1) & (blockCacheSize - 1))
	if block := e.blockCache[slot]; block != nil && block.start == start && block.generation == e.blockCacheGeneration {
		e.cachedBlockStart, e.cachedBlock = start, block
		return block, nil
	}

	block := &basicBlock{start: start, generation: e.blockCacheGeneration}
	pc := start
	page := start &^ uint64(pageMask)
	for len(block.instructions) < maxBlockInstructions {
		if pc&^uint64(pageMask) != page {
			break
		}
		d, err := e.cachedDecode(pc)
		if err != nil {
			if len(block.instructions) == 0 {
				return nil, err
			}
			break
		}
		if d.insnID != noInsnHook {
			break
		}
		block.instructions = append(block.instructions, d)
		pc += uint64(d.len)
		if d.endsBlock {
			break
		}
	}
	if len(block.instructions) == 0 {
		return nil, nil
	}
	e.blockCache[slot] = block
	e.cachedBlockStart, e.cachedBlock = start, block
	return block, nil
}

func (e *Engine) executeBlock(block *basicBlock, until uint64) error {
	if e.regs.rip != block.start {
		return nil
	}
	pc := block.start
	if until == 0 {
		for i, d := range block.instructions {
			if e.stopRequested {
				return nil
			}
			if i != 0 {
				e.trace[e.traceIdx] = pc
				e.traceIdx = (e.traceIdx + 1) % len(e.trace)
			}
			e.curInstrEnd = pc + uint64(d.len)
			branched, err := d.exec(e)
			if err != nil {
				return err
			}
			if !branched {
				e.regs.rip = e.curInstrEnd
			}
			if e.mem.consumeCodeDirty() {
				e.invalidateCodeCaches()
				return nil
			}
			if branched {
				return nil
			}
			pc = e.regs.rip
		}
		return nil
	}
	for i, d := range block.instructions {
		if e.stopRequested || e.regs.rip == until {
			return nil
		}
		if i != 0 {
			e.trace[e.traceIdx] = pc
			e.traceIdx = (e.traceIdx + 1) % len(e.trace)
		}
		e.curInstrEnd = pc + uint64(d.len)
		branched, err := d.exec(e)
		if err != nil {
			return err
		}
		if !branched {
			e.regs.rip = e.curInstrEnd
		}
		if e.mem.consumeCodeDirty() {
			e.invalidateCodeCaches()
			return nil
		}
		if branched {
			return nil
		}
		pc = e.regs.rip
	}
	return nil
}

func (e *Engine) invalidateCodeCaches() {
	e.decodeCache = make(map[uint64]*decodedPage)
	e.cachedDecodePage = nil
	e.blockCacheGeneration++
	e.cachedBlockStart = 0
	e.cachedBlock = nil
}

func (e *Engine) SetBlockJIT(enabled bool) {
	if e.blockJIT == enabled {
		return
	}
	e.blockJIT = enabled
	e.invalidateCodeCaches()
}
