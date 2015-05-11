package binconv

func Zeros(size int64) []byte {
	return make([]byte, size, size)
}
