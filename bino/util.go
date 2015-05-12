package bino

func Cstr(text string) []byte {
	return append([]byte(text), 0)
}

func Zeros(size int64) []byte {
	return make([]byte, size, size)
}
