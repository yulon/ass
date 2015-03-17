package ass

import (
	"os"
	"bytes"
	"errors"
)

type FileWriteManager struct{
	f *os.File
	labels map[string]int64
	pits []pit
	start int64
}

type pit struct{
	addr int64
	start string
	end string
	offset int64
	bit int
}

func NewFileWriteManager(f *os.File) *FileWriteManager {
	fwm := &FileWriteManager{
		f: f,
		labels: map[string]int64{},
		pits: []pit{},
	}
	fwm.start = fwm.Len()
	return fwm
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

func (fwm *FileWriteManager) Write(data interface{}) {
	fwm.f.Write(bin(data))
}

func (fwm *FileWriteManager) WriteStrict(data interface{}, size int) {
	b := bin(data)
	l := len(b)
	if l < size {
		fwm.Write(b)
		fwm.WriteSpace(size - l)
	}else{
		fwm.Write(b[:size])
	}
}

func (fwm *FileWriteManager) WriteSpace(count int) {
	fwm.Write(bytes.Repeat([]byte{0}, count))
}

func (fwm *FileWriteManager) writeAt(data interface{}, offset int64) {
	fwm.f.WriteAt(bin(data), offset)
}

func (fwm *FileWriteManager) Label(key string) {
	fwm.labels[key] = fwm.Len()
}

func (fwm *FileWriteManager) Len() int64 {
	fi, err := fwm.f.Stat()
	if err != nil {
		return 0
	}
	return fi.Size()
}

const(
	Bit8 = 1
	Bit16 = 2
	Bit32 = 4
	Bit64 = 8
)

func (fwm *FileWriteManager) WriteDifference(startLabel string, endLabel string, offset int64, bit int) {
	fwm.pits = append(fwm.pits, pit{
		addr: fwm.Len(),
		start: startLabel,
		end: endLabel,
		offset: offset,
		bit: bit,
	})
	fwm.WriteSpace(bit)
}

func (fwm *FileWriteManager) WritePointer(label string, bit int) {
	fwm.WriteDifference("", label, 0, bit)
}

func (fwm *FileWriteManager) WriteCurrent(bit int) {
	fwm.WriteDifference("", "", 0, bit)
}

func (fwm *FileWriteManager) WriteRelative(label string, bit int) {
	fwm.WriteDifference(label, "", 0, bit)
}

func (fwm *FileWriteManager) Fill() error {
	for i := 0; i < len(fwm.pits); i++ {
		var start, end int64
		var ok bool

		if fwm.pits[i].start == "" {
			start = 0
		}else{
			start, ok = fwm.labels[fwm.pits[i].start]
			if !ok {
				return errors.New(fwm.pits[i].start + " is not found")
			}
		}

		if fwm.pits[i].end == "" {
			end = fwm.pits[i].addr
		}else{
			end, ok = fwm.labels[fwm.pits[i].end]
			if !ok {
				return errors.New(fwm.pits[i].end + " is not found")
			}
		}
		n := end - start + fwm.pits[i].offset
		//println(fwm.pits[i].start, fwm.pits[i].end, fwm.labels[fwm.pits[i].start], fwm.labels[fwm.pits[i].end], start, end)
		switch fwm.pits[i].bit {
			case Bit8:
				fwm.writeAt(int8(n), fwm.pits[i].addr)
			case Bit16:
				fwm.writeAt(int16(n), fwm.pits[i].addr)
			case Bit32:
				fwm.writeAt(int32(n), fwm.pits[i].addr)
			case Bit64:
				fwm.writeAt(n, fwm.pits[i].addr)
		}
	}
	return nil
}