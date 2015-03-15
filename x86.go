package ass

type X86 struct{
	m Maker
}

func NewX86(m Maker) *X86 {
	return &X86{
		m: m,
	}
}

func (x86 *X86) JMP(key string) {
	x86.m.Write([]byte{255})
	x86.m.WriteMemoryAddress(key, BIT_32)
}
