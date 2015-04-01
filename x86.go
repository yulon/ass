package ass

import (
	"io"
)

const MACHINE_X86 = 4

type x86 struct{
	w io.Writer
}

func (x86 *x86) Reg() {
	x86.w.Write([]byte{184})
}

func (x86 *x86) Adi() {
	x86.w.Write([]byte{139, 0})
}

func (x86 *x86) Sep() {
	x86.w.Write([]byte{80})
}

func (x86 *x86) Cal() {
	x86.w.Write([]byte{255, 208})
}