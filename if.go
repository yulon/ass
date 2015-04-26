package ass

type ExecutableFileMaker interface{
	Write([]byte)(int, error)
	WrlabVA(string, BinNumTranslator)
}

type QpcodeWriter interface{
	MovRegImm(int, interface{})
	MovRegMem(int, interface{}, uint8)
	PushReg(int)
	Pop(int)
	CallReg(int)
}
