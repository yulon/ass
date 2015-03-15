package ass

import (
	"os"
	"errors"
)

type baseMaker struct{
	f *os.File
	marks map[string]int64
	pits []pit
	next int64
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
		f: f,
		marks: map[string]int64{},
		pits: []pit{},
	}, err
}

var DataTypeError = errors.New("Data Type Error")

func toBin(data interface{}) ([]byte, error) {
	switch d := data.(type){
		case []byte:
			return d, nil
		case string:
			return []byte(d), nil
		case int32:
			return []byte{byte(d), byte(d >> 8), byte(d >> 16), byte(d >> 24)}, nil
		case uint32:
			return []byte{byte(d), byte(d >> 8), byte(d >> 16), byte(d >> 24)}, nil
		case int16:
			return []byte{byte(d), byte(d >> 8)}, nil
		case uint16:
			return []byte{byte(d), byte(d >> 8)}, nil
		case int8:
			return []byte{byte(d)}, nil
		case uint8:
			return []byte{d}, nil
		case int64:
			return []byte{byte(d), byte(d >> 8), byte(d >> 16), byte(d >> 24), byte(d >> 32), byte(d >> 40), byte(d >> 48), byte(d >> 56)}, nil
		case uint64:
			return []byte{byte(d), byte(d >> 8), byte(d >> 16), byte(d >> 24), byte(d >> 32), byte(d >> 40), byte(d >> 48), byte(d >> 56)}, nil
		default:
			return nil, DataTypeError
	}
}

func (bm *baseMaker) Write(data interface{}) error {
	b, e := toBin(data)
	if e != nil {
		return e
	}

	l, e := bm.f.Write(b)
	if e != nil {
		return e
	}

	bm.next += int64(l)
	return nil
}

func (bm *baseMaker) writeAt(data interface{}, offset int64) error {
	b, e := toBin(data)
	if e != nil {
		return e
	}
	_, e = bm.f.WriteAt(b, offset)
	if e != nil {
		return e
	}
	return nil
}

func (bm *baseMaker) Label(key string) {
	bm.marks[key] = bm.next
}

const(
	BIT_8 = 1
	BIT_16 = 2
	BIT_32 = 4
	BIT_64 = 8
)

func (bm *baseMaker) WriteRelative(startLabel string, endLabel string, offset int64, bit uint8) error {
	err := bm.Write(make([]byte, bit, bit))
	if err != nil {
		return err
	}

	bm.pits = append(bm.pits, pit{
		addr: bm.next,
		start: startLabel,
		end: endLabel,
		offset: offset,
		bit: bit,
	})

	return nil
}

func (bm *baseMaker) WriteFilePointer(mark string, bit uint8) error {
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

		n := end - start + bm.pits[i].offset
		switch bm.pits[i].bit {
			case BIT_8:
				bm.writeAt(int8(n), bm.pits[i].addr)
			case BIT_16:
				bm.writeAt(int16(n), bm.pits[i].addr)
			case BIT_32:
				bm.writeAt(int32(n), bm.pits[i].addr)
			case BIT_64:
				bm.writeAt(n, bm.pits[i].addr)
		}
	}
	return bm.f.Close()
}