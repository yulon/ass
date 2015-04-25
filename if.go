package ass

type ExecutableFileMaker interface{
	WriteBinLibFnPtr(string, string)
}

type InstructionSet interface{
	Close() error
	MovRegNum(string, interface{}) error
	MovRegPtr(string, interface{}) error
	Push(interface{}) error
	Pop(string)
	CallReg(string)
}
