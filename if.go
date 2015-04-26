package ass

type ExecutableFileMaker interface{
	Write([]byte)(int, error)
	WrlabVA(string)
}

type MachineCodeWriter interface{
	MovRegNum(int, interface{})
	MovRegPtr(int, interface{}, uint8)
	PushReg(int)
	Pop(int)
	CallReg(int)
}
