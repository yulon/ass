package ass

import (
	"encoding/binary"
)

type BinNumTranslator func(interface{})[]byte

func BinNum8(num interface{}) (bin []byte) {
	switch n := num.(type){
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

func binNum16(num interface{}, bo binary.ByteOrder) []byte {
	bin := make([]byte, 8, 8)
	switch n := num.(type){
		case int:
			bo.PutUint16(bin, uint16(n))
		case int8:
			bo.PutUint16(bin, uint16(n))
		case int16:
			bo.PutUint16(bin, uint16(n))
		case int32:
			bo.PutUint16(bin, uint16(n))
		case int64:
			bo.PutUint16(bin, uint16(n))
		case uint8:
			bo.PutUint16(bin, uint16(n))
		case uint16:
			bo.PutUint16(bin, n)
		case uint32:
			bo.PutUint16(bin, uint16(n))
		case uint64:
			bo.PutUint16(bin, uint16(n))
	}
	return bin[:2]
}

func binNum32(num interface{}, bo binary.ByteOrder) []byte {
	bin := make([]byte, 8, 8)
	switch n := num.(type){
		case int:
			bo.PutUint32(bin, uint32(n))
		case int8:
			bo.PutUint32(bin, uint32(n))
		case int16:
			bo.PutUint32(bin, uint32(n))
		case int32:
			bo.PutUint32(bin, uint32(n))
		case int64:
			bo.PutUint32(bin, uint32(n))
		case uint8:
			bo.PutUint32(bin, uint32(n))
		case uint16:
			bo.PutUint32(bin, uint32(n))
		case uint32:
			bo.PutUint32(bin, n)
		case uint64:
			bo.PutUint32(bin, uint32(n))
	}
	return bin[:4]
}

func binNum64(num interface{}, bo binary.ByteOrder) []byte {
	bin := make([]byte, 8, 8)
	switch n := num.(type){
		case int:
			bo.PutUint64(bin, uint64(n))
		case int8:
			bo.PutUint64(bin, uint64(n))
		case int16:
			bo.PutUint64(bin, uint64(n))
		case int32:
			bo.PutUint64(bin, uint64(n))
		case int64:
			bo.PutUint64(bin, uint64(n))
		case uint8:
			bo.PutUint64(bin, uint64(n))
		case uint16:
			bo.PutUint64(bin, uint64(n))
		case uint32:
			bo.PutUint64(bin, uint64(n))
		case uint64:
			bo.PutUint64(bin, n)
	}
	return bin
}

func BinNum16L(num interface{}) []byte {
	return binNum16(num, binary.LittleEndian)
}

func BinNum32L(num interface{}) []byte {
	return binNum32(num, binary.LittleEndian)
}

func BinNum64L(num interface{}) []byte {
	return binNum64(num, binary.LittleEndian)
}

func BinNum16B(num interface{}) []byte {
	return binNum16(num, binary.BigEndian)
}

func BinNum32B(num interface{}) []byte {
	return binNum32(num, binary.BigEndian)
}

func BinNum64B(num interface{}) []byte {
	return binNum64(num, binary.BigEndian)
}

func Chars(text string) []byte {
	return append([]byte(text), 0)
}

func Chars32(text string) (bin []byte) {
	bin = make([]byte, 4, 4)
	copy(bin, []byte(text))
	return
}

func Chars64(text string) (bin []byte) {
	bin = make([]byte, 8, 8)
	copy(bin, []byte(text))
	return
}
