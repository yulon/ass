package ass

import (
	"os"
)

type baseMaker struct{
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

func NewBaseMaker(path string) (*baseMaker, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	return &baseMaker{
		File: f,
		marks: map[string]int64{},
		pits: []pit{},
	}, err
}

func (bm *baseMaker) Mark(key string) {
	bm.marks[key] = bm.Next()
}

func (bm *baseMaker) Next() int64 {
	fi, _ := bm.Stat()
	return fi.Size()
}

const(
	BIT_8 = 1
	BIT_16 = 2
	BIT_32 = 4
	BIT_64 = 8
)

func (bm *baseMaker) WriteRelative(startMark string, endMark string, offset int64, bit uint8) error {
	bm.pits = append(bm.pits, pit{
		addr: bm.Next(),
		start: startMark,
		end: endMark,
		offset: offset,
		bit: bit,
	})
	_, err := bm.Write(make([]byte, bit, bit))
	return err
}

func (bm *baseMaker) WriteFileOffset(mark string, bit uint8) error {
	return bm.WriteRelative("", mark, 0, bit)
}

func (bm *baseMaker) Close() error {
	for i := 0; i < len(bm.pits); i++ {
		var start, end int64

		if bm.pits[i].start == "" {
			start = 0
		}else{
			start = bm.marks[bm.pits[i].start]
		}

		if bm.pits[i].end == "" {
			end = bm.pits[i].addr
		}else{
			end = bm.marks[bm.pits[i].end]
		}

		i64 := end - start + bm.pits[i].offset
		var data []byte
		switch bm.pits[i].bit {
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
		bm.WriteAt(data, bm.pits[i].addr)
	}
	return bm.File.Close()
}