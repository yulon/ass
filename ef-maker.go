package ass

type ExecutableFileMaker interface{
	Write([]byte) (int, error)
	Label(string)
	WriteMemoryAddress(string, uint8)
}