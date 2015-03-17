package ass

import (
	"os"
	"bytes"
	"errors"
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
	bit int
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

func bin(data interface{}) []byte {
	switch d := data.(type){
		case []byte:
			return d
		case string:
			return []byte(d)
		case int:
			return []byte{byte(d), byte(d >> 8), byte(d >> 16), byte(d >> 24), byte(d >> 32), byte(d >> 40), byte(d >> 48), byte(d >> 56)}
		case uint:
			return []byte{byte(d), byte(d >> 8), byte(d >> 16), byte(d >> 24), byte(d >> 32), byte(d >> 40), byte(d >> 48), byte(d >> 56)}
		case int32:
			return []byte{byte(d), byte(d >> 8), byte(d >> 16), byte(d >> 24)}
		case uint32:
			return []byte{byte(d), byte(d >> 8), byte(d >> 16), byte(d >> 24)}
		case int16:
			return []byte{byte(d), byte(d >> 8)}
		case uint16:
			return []byte{byte(d), byte(d >> 8)}
		case int8:
			return []byte{byte(d)}
		case uint8:
			return []byte{d}
		case int64:
			return []byte{byte(d), byte(d >> 8), byte(d >> 16), byte(d >> 24), byte(d >> 32), byte(d >> 40), byte(d >> 48), byte(d >> 56)}
		case uint64:
			return []byte{byte(d), byte(d >> 8), byte(d >> 16), byte(d >> 24), byte(d >> 32), byte(d >> 40), byte(d >> 48), byte(d >> 56)}
		default:
			return nil
	}
}

func (bm *baseMaker) Write(data interface{}) {
	l, _ := bm.f.Write(bin(data))
	bm.leng += int64(l)
}

func (bm *baseMaker) WriteSolid(data interface{}, size int) {
	b := bin(data)
	l := len(b)
	if l < size {
		bm.Write(b)
		bm.WriteSpace(size - l)
	}else{
		bm.Write(b[:size])
	}
}

func (bm *baseMaker) WriteSpace(count int) {
	bm.Write(bytes.Repeat([]byte{0}, count))
}

func (bm *baseMaker) writeAt(data interface{}, offset int64) {
	bm.f.WriteAt(bin(data), offset)
}

func (bm *baseMaker) Label(key string) {
	bm.labels[key] = bm.leng
}

func (bm *baseMaker) Len() int64 {
	return bm.leng
}

const(
	Bit8 = 1
	Bit16 = 2
	Bit32 = 4
	Bit64 = 8
)

func (bm *baseMaker) WriteDifference(startLabel string, endLabel string, offset int64, bit int) {
	bm.pits = append(bm.pits, pit{
		addr: bm.leng,
		start: startLabel,
		end: endLabel,
		offset: offset,
		bit: bit,
	})
	bm.WriteSpace(bit)
}

func (bm *baseMaker) WritePointer(label string, bit int) {
	bm.WriteDifference("", label, 0, bit)
}

func (bm *baseMaker) WriteCurrent(bit int) {
	bm.WriteDifference("", "", 0, bit)
}

func (bm *baseMaker) WriteRelative(label string, bit int) {
	bm.WriteDifference(label, "", 0, bit)
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
			case Bit8:
				bm.writeAt(int8(n), bm.pits[i].addr)
			case Bit16:
				bm.writeAt(int16(n), bm.pits[i].addr)
			case Bit32:
				bm.writeAt(int32(n), bm.pits[i].addr)
			case Bit64:
				bm.writeAt(n, bm.pits[i].addr)
		}
	}
	return bm.f.Close()
}