package ass

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type NumBitOrder func(interface{})[]byte

var (
	nboNum8 = fmt.Sprint(Num8)
	nboNum16L = fmt.Sprint(Num16L)
	nboNum32L = fmt.Sprint(Num32L)
	nboNum64L = fmt.Sprint(Num64L)
	nboNum16B = fmt.Sprint(Num16B)
	nboNum32B = fmt.Sprint(Num32B)
	nboNum64B = fmt.Sprint(Num64B)
)

func Num8(num interface{}) (bin []byte) {
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

func num16(num interface{}, bo binary.ByteOrder) []byte {
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

func num32(num interface{}, bo binary.ByteOrder) []byte {
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

func num64(num interface{}, bo binary.ByteOrder) []byte {
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

func Num16L(num interface{}) []byte {
	return num16(num, binary.LittleEndian)
}

func Num32L(num interface{}) []byte {
	return num32(num, binary.LittleEndian)
}

func Num64L(num interface{}) []byte {
	return num64(num, binary.LittleEndian)
}

func Num16B(num interface{}) []byte {
	return num16(num, binary.BigEndian)
}

func Num32B(num interface{}) []byte {
	return num32(num, binary.BigEndian)
}

func Num64B(num interface{}) []byte {
	return num64(num, binary.BigEndian)
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

func Zeros(size int) []byte {
	return bytes.Repeat([]byte{0}, size)
}
