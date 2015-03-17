package ass

const CPU_X86 = 32

type X86Writer struct{
	m ExecutableFileMaker
}

func NewX86Writer(m ExecutableFileMaker) *X86Writer {
	return &X86Writer{
		m: m,
	}
}

func (x86 *X86Writer) JMP(key string) {
	x86.m.Write([]byte{255})
	x86.m.WriteMemoryAddress(key, Bit32)
}
