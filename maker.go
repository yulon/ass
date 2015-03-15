package ass

type Maker interface{
	Write([]byte) (int, error)
	Mark(string)
	WriteMemoryAddress(string, uint8)
}