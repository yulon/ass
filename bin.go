package ass

import (
	"encoding/binary"
)

type IntX interface{}

func Bin8(intx IntX) (bin []byte) {
	switch n := intx.(type){
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

func bin16(intx IntX, bo binary.ByteOrder) []byte {
	bin := make([]byte, 8, 8)
	switch n := intx.(type){
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

func bin32(intx IntX, bo binary.ByteOrder) []byte {
	bin := make([]byte, 8, 8)
	switch n := intx.(type){
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

func bin64(intx IntX, bo binary.ByteOrder) []byte {
	bin := make([]byte, 8, 8)
	switch n := intx.(type){
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

func Bin16L(intx IntX) []byte {
	return bin16(intx, binary.LittleEndian)
}

func Bin32L(intx IntX) []byte {
	return bin32(intx, binary.LittleEndian)
}

func Bin64L(intx IntX) []byte {
	return bin64(intx, binary.LittleEndian)
}

func Bin16B(intx IntX) []byte {
	return bin16(intx, binary.BigEndian)
}

func Bin32B(intx IntX) []byte {
	return bin32(intx, binary.BigEndian)
}

func Bin64B(intx IntX) []byte {
	return bin64(intx, binary.BigEndian)
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
