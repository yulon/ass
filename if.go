package ass

type ExecutableFileMaker interface{
	Write([]byte)(int, error)
	WrlabVA(string)
}

type MachineCodeWriter interface{
	MovRegNum(uint16, interface{})
	MovRegPtr(uint16, interface{}, uint8)
	PushReg(uint16)
	Pop(uint16)
	CallReg(uint16)
}
