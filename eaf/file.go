package ass

import (
	"os"
)

func fSize(f *os.File) int64 {
	fi, err := f.Stat()
	if err != nil {
		return 0
	}
	return fi.Size()
}

func fAlign(f *os.File, size int64) {
	m := fSize(f) % size
	if m > 0 {
		f.Write(Zeros(size - m))
	}
}
