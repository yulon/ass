package bin

import (
	"encoding/binary"
	"fmt"
)

type IntConv func(interface{}) []byte

func SameIntConv(one IntConv, two IntConv) bool {
	return fmt.Sprint(one) == fmt.Sprint(two)
}

func Int8(i interface{}) (bin []byte) {
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

func i16(i interface{}, bo binary.ByteOrder) []byte {
	bin := make([]byte, 8, 8)
	switch n := i.(type) {
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

func i32(i interface{}, bo binary.ByteOrder) []byte {
	bin := make([]byte, 8, 8)
	switch n := i.(type) {
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

func i64(i interface{}, bo binary.ByteOrder) []byte {
	bin := make([]byte, 8, 8)
	switch n := i.(type) {
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

func Int16L(i interface{}) []byte {
	return i16(i, binary.LittleEndian)
}

func Int32L(i interface{}) []byte {
	return i32(i, binary.LittleEndian)
}

func Int64L(i interface{}) []byte {
	return i64(i, binary.LittleEndian)
}

func Int16B(i interface{}) []byte {
	return i16(i, binary.BigEndian)
}

func Int32B(i interface{}) []byte {
	return i32(i, binary.BigEndian)
}

func Int64B(i interface{}) []byte {
	return i64(i, binary.BigEndian)
}
