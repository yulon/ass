package bin

func Cstr(text string) []byte {
	return append([]byte(text), 0)
}

func Cstr32(text string) (bin []byte) {
	bin = make([]byte, 4, 4)
	copy(bin, []byte(text))
	return
}

func Cstr64(text string) (bin []byte) {
	bin = make([]byte, 8, 8)
	copy(bin, []byte(text))
	return
}
