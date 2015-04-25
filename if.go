package ass

type ExecutableFileMaker interface{
	Write(data interface{})
	WrlabVA(string)
}

type MachineCodeWriter interface{
	MovRegNum(string, interface{})
	MovRegPtr(string, interface{}, uint8)
	PushReg(string)
	Pop(string)
	CallReg(string)
}
