package ass

import (
	"os"
)

type File struct{
	*os.File
	marks map[string]int64
	pits []pit
}

type pit struct{
	addr int64
	start string
	end string
	offset int64
	bit uint8
}

func CreateFile(path string) (*File, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	return &File{
		File: f,
		marks: map[string]int64{},
		pits: []pit{},
	}, err
}

func (f *File) Mark(key string) {
	f.marks[key] = f.Next()
}

func (f *File) Next() int64 {
	fi, _ := f.Stat()
	return fi.Size()
}

const(
	BIT_8 = 1
	BIT_16 = 2
	BIT_32 = 4
	BIT_64 = 8
)

func (f *File) WriteRelative(startMark string, endMark string, offset int64, bit uint8) error {
	f.pits = append(f.pits, pit{
		addr: f.Next(),
		start: startMark,
		end: endMark,
		offset: offset,
		bit: bit,
	})
	_, err := f.Write(make([]byte, bit, bit))
	return err
}

func (f *File) WriteFileOffset(mark string, bit uint8) error {
	return f.WriteRelative("", mark, 0, bit)
}

func (f *File) Close() error {
	for i := 0; i < len(f.pits); i++ {
		var start, end int64

		if f.pits[i].start == "" {
			start = 0
		}else{
			start = f.marks[f.pits[i].start]
		}

		if f.pits[i].end == "" {
			end = f.pits[i].addr
		}else{
			end = f.marks[f.pits[i].end]
		}

		i64 := end - start + f.pits[i].offset
		var data []byte
		switch f.pits[i].bit {
			case BIT_8:
				i8 := int8(i64)
				data = []byte{byte(i8)}
			case BIT_16:
				i16 := int8(i64)
				data = []byte{byte(i16), byte(i16 >> 8)}
			case BIT_32:
				i32 := int8(i64)
				data = []byte{byte(i32), byte(i32 >> 8), byte(i32 >> 16), byte(i32 >> 24)}
			case BIT_64:
				data = []byte{byte(i64), byte(i64 >> 8), byte(i64 >> 16), byte(i64 >> 24),
					byte(i64 >> 32), byte(i64 >> 40), byte(i64 >> 48), byte(i64 >> 56),
				}
		}
		f.WriteAt(data, f.pits[i].addr)
	}
	return f.File.Close()
}