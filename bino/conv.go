package bino

import (
	"encoding/binary"
)

type Converter func(interface{}) []byte

func Byte(i interface{}) (bin []byte) {
	switch n := i.(type) {
		case int:
			bin = []byte{uint8(n)}
		case int8:
			bin = []byte{uint8(n)}
		case int16:
			bin = []byte{uint8(n)}
		case int32:
			bin = []byte{uint8(n)}
		case int64:
			bin = []byte{uint8(n)}
		case uint8:
			bin = []byte{n}
		case uint16:
			bin = []byte{uint8(n)}
		case uint32:
			bin = []byte{uint8(n)}
		case uint64:
			bin = []byte{uint8(n)}
	}
	return
}

func word(i interface{}, order binary.ByteOrder) []byte {
	bin := make([]byte, 8, 8)
	switch n := i.(type) {
		case int:
			order.PutUint16(bin, uint16(n))
		case int8:
			order.PutUint16(bin, uint16(n))
		case int16:
			order.PutUint16(bin, uint16(n))
		case int32:
			order.PutUint16(bin, uint16(n))
		case int64:
			order.PutUint16(bin, uint16(n))
		case uint8:
			order.PutUint16(bin, uint16(n))
		case uint16:
			order.PutUint16(bin, n)
		case uint32:
			order.PutUint16(bin, uint16(n))
		case uint64:
			order.PutUint16(bin, uint16(n))
		case string:
			if order == binary.BigEndian {
				for i := 0; i < len(n); i++ {
					bin[1-i] = n[i]
				}
			}else{
				copy(bin, []byte(n))
			}
	}
	return bin[:2]
}

func dword(i interface{}, order binary.ByteOrder) []byte {
	bin := make([]byte, 8, 8)
	switch n := i.(type) {
		case int:
			order.PutUint32(bin, uint32(n))
		case int8:
			order.PutUint32(bin, uint32(n))
		case int16:
			order.PutUint32(bin, uint32(n))
		case int32:
			order.PutUint32(bin, uint32(n))
		case int64:
			order.PutUint32(bin, uint32(n))
		case uint8:
			order.PutUint32(bin, uint32(n))
		case uint16:
			order.PutUint32(bin, uint32(n))
		case uint32:
			order.PutUint32(bin, n)
		case uint64:
			order.PutUint32(bin, uint32(n))
		case string:
			if order == binary.BigEndian {
				for i := 0; i < len(n); i++ {
					bin[3-i] = n[i]
				}
			}else{
				copy(bin, []byte(n))
			}
	}
	return bin[:4]
}

func qword(i interface{}, order binary.ByteOrder) []byte {
	bin := make([]byte, 8, 8)
	switch n := i.(type) {
		case int:
			order.PutUint64(bin, uint64(n))
		case int8:
			order.PutUint64(bin, uint64(n))
		case int16:
			order.PutUint64(bin, uint64(n))
		case int32:
			order.PutUint64(bin, uint64(n))
		case int64:
			order.PutUint64(bin, uint64(n))
		case uint8:
			order.PutUint64(bin, uint64(n))
		case uint16:
			order.PutUint64(bin, uint64(n))
		case uint32:
			order.PutUint64(bin, uint64(n))
		case uint64:
			order.PutUint64(bin, n)
		case string:
			if order == binary.BigEndian {
				for i := 0; i < len(n); i++ {
					bin[7-i] = n[i]
				}
			}else{
				copy(bin, []byte(n))
			}
	}
	return bin
}

func Word(i interface{}) []byte {
	return word(i, binary.LittleEndian)
}

func Dword(i interface{}) []byte {
	return dword(i, binary.LittleEndian)
}

func Qword(i interface{}) []byte {
	return qword(i, binary.LittleEndian)
}

func WordB(i interface{}) []byte {
	return word(i, binary.BigEndian)
}

func DwordB(i interface{}) []byte {
	return dword(i, binary.BigEndian)
}

func QwordB(i interface{}) []byte {
	return qword(i, binary.BigEndian)
}
