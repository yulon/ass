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
