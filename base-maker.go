package ass

import (
	"os"
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

func (bm *baseMaker) Write(data []byte) (int64, error) {
	l, e := bm.f.Write(data)
	if e != nil {
		return 0, e
	}
	l64 := int64(l)
	bm.next += l64
	return l64, nil
}

func (bm *baseMaker) WriteString(data string) (int64, error) {
	return bm.Write([]byte(data))
}

func (bm *baseMaker) WriteInt8(n int64) (int64, error) {
	i := int8(n)
	return bm.Write([]byte{byte(i)})
}

func (bm *baseMaker) WriteInt16(n int64) (int64, error) {
	i := int16(n)
	return bm.Write([]byte{byte(i), byte(i >> 8)})
}

func (bm *baseMaker) WriteInt32(n int64) (int64, error) {
	i := int32(n)
	return bm.Write([]byte{byte(i), byte(i >> 8), byte(i >> 16), byte(i >> 24)})
}

func (bm *baseMaker) WriteInt64(i int64) (int64, error) {
	return bm.Write([]byte{byte(i), byte(i >> 8), byte(i >> 16), byte(i >> 24), byte(i >> 32), byte(i >> 40), byte(i >> 48), byte(i >> 56)})
}

func (bm *baseMaker) writeAt(data []byte, offset int64) (int64, error) {
	l, e := bm.f.WriteAt(data, offset)
	if e != nil {
		return 0, e
	}
	l64 := int64(l)
	bm.next += l64
	return l64, nil
}

func (bm *baseMaker) writeInt8At(n int64, offset int64) (int64, error) {
	i := int8(n)
	return bm.writeAt([]byte{byte(i)}, offset)
}

func (bm *baseMaker) writeInt16At(n int64, offset int64) (int64, error) {
	i := int16(n)
	return bm.writeAt([]byte{byte(i), byte(i >> 8)}, offset)
}

func (bm *baseMaker) writeInt32At(n int64, offset int64) (int64, error) {
	i := int32(n)
	return bm.writeAt([]byte{byte(i), byte(i >> 8), byte(i >> 16), byte(i >> 24)}, offset)
}

func (bm *baseMaker) writeInt64At(i int64, offset int64) (int64, error) {
	return bm.writeAt([]byte{byte(i), byte(i >> 8), byte(i >> 16), byte(i >> 24), byte(i >> 32), byte(i >> 40), byte(i >> 48), byte(i >> 56)}, offset)
}

func (bm *baseMaker) Mark(key string) {
	bm.marks[key] = bm.next
}

const(
	BIT_8 = 1
	BIT_16 = 2
	BIT_32 = 4
	BIT_64 = 8
)

func (bm *baseMaker) WriteRelative(startMark string, endMark string, offset int64, bit uint8) error {
	bm.pits = append(bm.pits, pit{
		addr: bm.next,
		start: startMark,
		end: endMark,
		offset: offset,
		bit: bit,
	})
	_, err := bm.Write(make([]byte, bit, bit))
	return err
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
				bm.writeInt8At(n, bm.pits[i].addr)
			case BIT_16:
				bm.writeInt16At(n, bm.pits[i].addr)
			case BIT_32:
				bm.writeInt32At(n, bm.pits[i].addr)
			case BIT_64:
				bm.writeInt64At(n, bm.pits[i].addr)
		}
	}
	return bm.f.Close()
}