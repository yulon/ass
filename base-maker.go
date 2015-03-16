package ass

import (
	"os"
	"errors"
	"bytes"
)

type baseMaker struct{
	f *os.File
	labels map[string]int64
	pits []pit
	leng int64
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
		labels: map[string]int64{},
		pits: []pit{},
		leng: 0,
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

func (bm *baseMaker) Write(data interface{}) (int, error) {
	b, e := toBin(data)
	if e != nil {
		return 0, e
	}

	l, e := bm.f.Write(b)
	if e != nil {
		return 0, e
	}

	bm.leng += int64(l)
	return l, nil
}

func (bm *baseMaker) WriteSpace(count int) (int, error) {
	return bm.Write(bytes.Repeat([]byte{0}, count))
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
	bm.labels[key] = bm.leng
}

func (bm *baseMaker) Len() int64 {
	return bm.leng
}

const(
	BIT_8 = 1
	BIT_16 = 2
	BIT_32 = 4
	BIT_64 = 8
)

func (bm *baseMaker) WriteRelative(startLabel string, endLabel string, offset int64, bit uint8) error {
	bm.pits = append(bm.pits, pit{
		addr: bm.leng,
		start: startLabel,
		end: endLabel,
		offset: offset,
		bit: bit,
	})
	_, err := bm.WriteSpace(int(bit))
	return err
}

func (bm *baseMaker) WriteFilePointer(label string, bit uint8) error {
	return bm.WriteRelative("", label, 0, bit)
}

func (bm *baseMaker) Close() error {
	for i := 0; i < len(bm.pits); i++ {
		var start, end int64
		var ok bool

		if bm.pits[i].start == "" {
			start = 0
		}else{
			start, ok = bm.labels[bm.pits[i].start]
			if !ok {
				bm.f.Close()
				return errors.New(bm.pits[i].start + " is not found")
			}
		}

		if bm.pits[i].end == "" {
			end = bm.pits[i].addr
		}else{
			end, ok = bm.labels[bm.pits[i].end]
			if !ok {
				bm.f.Close()
				return errors.New(bm.pits[i].end + " is not found")
			}
		}
		n := end - start + bm.pits[i].offset
		//println(bm.pits[i].start, bm.pits[i].end, bm.labels[bm.pits[i].start], bm.labels[bm.pits[i].end], start, end)
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