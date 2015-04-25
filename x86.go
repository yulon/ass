package ass

import (
	//"os"
	//"fmt"
	"errors"
)

const X86 = 4

type x86 struct{
	baseVA int64
	om *OutputManager
}

func (x86 *x86) Close() error {
	return x86.om.Fill()
}

var x86SufRegDif = map[string]byte{
	"eax": 0,
	"ebx": 3,
	"ecx": 1,
	"edx": 2,
	"esi": 6,
	"edi": 7,
	"ebp": 5,
	"esp": 4,
}

var TypeError = errors.New("Type error")

func (x86 *x86) switchWrite(n interface{}) error {
	switch v := n.(type){
		case int:
			x86.om.Write(int32(v))
			return nil
		case nil:
			return nil
		default:
			return TypeError
	}
}

func (x86 *x86) MovRegNum(dest string, src interface{}) error { // mov reg, num
	x86.om.Write([]byte{184 + x86SufRegDif[dest]})
	return x86.switchWrite(src)
}

func (x86 *x86) MovRegPtr(dest string, src interface{}) error { // mov reg, [ptr]
	switch dest {
		case "eax":
			x86.om.Write([]byte{161})
		case "ebx":
			x86.om.Write([]byte{139, 29})
		case "ecx":
			x86.om.Write([]byte{139, 13})
		case "edx":
			x86.om.Write([]byte{139, 21})
		case "esi":
			x86.om.Write([]byte{139, 53})
		case "edi":
			x86.om.Write([]byte{139, 61})
		case "ebp":
			x86.om.Write([]byte{139, 45})
		case "esp":
			x86.om.Write([]byte{139, 37})
	}
	return x86.switchWrite(src)
}

func (x86 *x86) Push(src interface{}) error {
	switch v := src.(type){
		case int:
			x86.om.Write([]byte{104})
			x86.om.Write(int32(v))
		case nil:
			x86.om.Write([]byte{104})
		case string:
			x86.om.Write([]byte{80 + x86SufRegDif[v]})
		default:
			return TypeError
	}
	return nil
}

func (x86 *x86) Pop(src string) {
	x86.om.Write([]byte{88 + x86SufRegDif[src]})
}

func (x86 *x86) CallReg(src string) {
	x86.om.Write([]byte{255, 208 + x86SufRegDif[src]})
}
