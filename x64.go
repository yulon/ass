package ass

import (
	"io"
)

const MACHINE_X64 = 8

type x64 struct{
	w io.Writer
}

func (x64 *x64) Reg() {
	x64.w.Write([]byte{72, 184})
}

func (x64 *x64) Adi() {
	x64.w.Write([]byte{72, 139, 00})
}

func (x64 *x64) Sep() {
	x64.w.Write([]byte{72, 137, 193})
}

func (x64 *x64) Cal() {
	x64.w.Write([]byte{255, 208})
}