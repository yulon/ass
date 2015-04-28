package ass

import (
	"io"
)

type QpcodeWriter interface{
	io.WriteCloser
	MovRegImm(int, interface{})
	MovRegMem(int, interface{}, uint8)
	PushReg(int)
	Pop(int)
	CallReg(int)
}
