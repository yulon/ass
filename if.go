package ass

type QpcodeWriter interface{
	MovRegImm(int, interface{})
	MovRegMem(int, interface{}, uint8)
	PushReg(int)
	Pop(int)
	CallReg(int)
}
