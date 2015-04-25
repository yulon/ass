package ass

import (
	"io"
	"bytes"
	"errors"
)

type OutputManager struct{
	o io.WriterAt
	labels map[string]int64
	pits []pit
	offset int64
}

type pit struct{
	addr int64
	offset string
	end string
	added int64
	bit int
}

func NewOutputManager(ws io.WriterAt, base int64) *OutputManager {
	om := &OutputManager{
		o: ws,
		labels: map[string]int64{},
		pits: []pit{},
	}
	om.offset = base
	return om
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

func (om *OutputManager) Write(data interface{}) (l int, err error) {
	l, err = om.o.WriteAt(bin(data), om.offset)
	if err != nil {
		return
	}
	om.offset += int64(l)
	return
}

func (om *OutputManager) WriteStrict(data interface{}, size int) {
	b := bin(data)
	l := len(b)
	if l < size {
		om.Write(b)
		om.WriteSpace(size - l)
	}else{
		om.Write(b[:size])
	}
}

func (om *OutputManager) WriteSpace(count int) {
	om.Write(bytes.Repeat([]byte{0}, count))
}

func (om *OutputManager) writeAt(data interface{}, added int64) {
	om.o.WriteAt(bin(data), added)
}

func (om *OutputManager) Label(l string) {
	om.labels[l] = om.offset
}

const(
	Bit8 = 1
	Bit16 = 2
	Bit32 = 4
	Bit64 = 8
)

func (om *OutputManager) WrlabOffset(offsetLabel string, endLabel string, added int64, bit int) {
	om.pits = append(om.pits, pit{
		addr: om.offset,
		offset: offsetLabel,
		end: endLabel,
		added: added,
		bit: bit,
	})
	om.WriteSpace(bit)
}

func (om *OutputManager) WrlabPointer(label string, bit int) {
	om.WrlabOffset("", label, 0, bit)
}

func (om *OutputManager) WrlabRelative(label string, bit int) {
	om.WrlabOffset(label, "", 0, bit)
}

func (om *OutputManager) Fill() error {
	for i := 0; i < len(om.pits); i++ {
		var offset, end int64
		var ok bool

		if om.pits[i].offset == "" {
			offset = om.offset
		}else{
			offset, ok = om.labels[om.pits[i].offset]
			if !ok {
				return errors.New(om.pits[i].offset + " is not found")
			}
		}

		if om.pits[i].end == "" {
			end = om.pits[i].addr
		}else{
			end, ok = om.labels[om.pits[i].end]
			if !ok {
				return errors.New(om.pits[i].end + " is not found")
			}
		}
		
		n := end - offset + om.pits[i].added
		switch om.pits[i].bit {
			case Bit8:
				om.writeAt(int8(n), om.pits[i].addr)
			case Bit16:
				om.writeAt(int16(n), om.pits[i].addr)
			case Bit32:
				om.writeAt(int32(n), om.pits[i].addr)
			case Bit64:
				om.writeAt(n, om.pits[i].addr)
		}
	}
	return nil
}