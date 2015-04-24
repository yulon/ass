package ass

type ExecutableFileMaker interface{
	Write(data interface{})
	WrlabVA(string)
	Close() error
}
