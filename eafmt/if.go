package eafmt

import "io"

type Writer interface{
	io.WriteSeeker
	GetVA() int64
}
