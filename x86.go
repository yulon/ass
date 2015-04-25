package ass

import (
	"os"
	"fmt"
)

const MACHINE_X86 = 4

type x86 struct{
	m ExecutableFileMaker
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

func (x86 *x86) swiol(iol interface{}) {
	switch v := iol.(type){
		case int:
			x86.m.Write(int32(v))
		case string:
			x86.m.WrlabVA(v)
		default:
			fmt.Println("Error: ", iol)
			x86.m.Close()
			os.Exit(1)
	}
}

func (x86 *x86) ValToReg(v interface{}, r string) { // mov reg, val
	x86.m.Write([]byte{184 + x86SufRegDif[r]})
	x86.swiol(v)
}

func (x86 *x86) PtrToReg(p interface{}, r string) { // mov reg, [ptr]
	switch r {
		case "eax":
			x86.m.Write([]byte{161})
		case "ebx":
			x86.m.Write([]byte{139, 29})
		case "ecx":
			x86.m.Write([]byte{139, 13})
		case "edx":
			x86.m.Write([]byte{139, 21})
		case "esi":
			x86.m.Write([]byte{139, 53})
		case "edi":
			x86.m.Write([]byte{139, 61})
		case "ebp":
			x86.m.Write([]byte{139, 45})
		case "esp":
			x86.m.Write([]byte{139, 37})
	}
	x86.swiol(p)
}

func (x86 *x86) Push(r string) {
	x86.m.Write([]byte{80 + x86SufRegDif[r]})
}

func (x86 *x86) Pop(r string) {
	x86.m.Write([]byte{88 + x86SufRegDif[r]})
}

func (x86 *x86) CallReg(r string) {
	x86.m.Write([]byte{255, 208 + x86SufRegDif[r]})
}
