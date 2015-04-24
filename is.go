package ass

type IS interface{
	ValToReg(interface{}, string)
	PtrToReg(interface{}, string)
	Push(string)
	Pop(string)
	CallReg(string)
}
