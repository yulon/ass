package ass

import (
	"os"
	"fmt"
)

const MACHINE_X86 = 4

type x86mcw struct{
	m ExecutableFileMaker
}

var x86Regs = map[string]byte{
	"eax": 0,
	"ebx": 3,
	"ecx": 1,
	"edx": 2,
	"esi": 6,
	"edi": 7,
	"ebp": 5,
	"esp": 4,
}

func (w *x86mcw) swiol(iol interface{}) {
	switch v := iol.(type){
		case int:
			w.m.Write(int32(v))
		case string:
			w.m.WrlabVA(v)
		default:
			fmt.Println("Error: ", iol)
			os.Exit(1)
	}
}

func (w *x86mcw) MovRegNum(dest string, src interface{}) {
	w.m.Write([]byte{184 | x86Regs[dest]})
	w.swiol(src)
}

func (w *x86mcw) MovRegPtr(dest string, src interface{}, bitSrc uint8) {
	if dest == "eax" {
		w.m.Write([]byte{161})
	}else{
		w.m.Write(uint16(1419 | x86Regs[dest] << 11)) // de10110001011
	}
	w.swiol(src)
}

func (w *x86mcw) MovRegReg(dest string, src string) {
	w.m.Write(uint16(49289 | x86Regs[src] << 11 | x86Regs[dest] << 8)) // 110sr0de10001001
}

func (w *x86mcw) PushReg(src string) {
	w.m.Write([]byte{80 | x86Regs[src]})
}

func (w *x86mcw) Pop(dest string) {
	w.m.Write([]byte{88 | x86Regs[dest]})
}

func (w *x86mcw) CallReg(dest string) {
	w.m.Write([]byte{53503 | x86Regs[dest] << 8}) // 110100RG11111111
}

var x86 = map[string]func([]interface{}) {
	"mov": func(p []interface{}){
		switch p[0] {
			
		}
	},
}

func ifToString(i interface{}) string {
	switch v := i.(type){
		case string:
			return v
	}
	return ""
}

func ifToInt(i interface{}) int {
	switch v := i.(type){
		case int:
			return v
	}
	return 0
}
