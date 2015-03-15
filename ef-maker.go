package ass

type ExecutableFileMaker interface{
	Write([]byte) (int, error)
	Mark(string)
	WriteMemoryAddress(string, uint8)
}