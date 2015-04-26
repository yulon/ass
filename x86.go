package ass

import (
	"os"
	"fmt"
)

const MACHINE_X86 = 4

type x86mcw struct{
	m ExecutableFileMaker
}

const (
	EAX = 0 //000
	EBX = 3 //011
	ECX = 1 //001
	EDX = 2 //010
	ESI = 6 //110
	EDI = 7 //111
	EBP = 5 //101
	ESP = 4 //100
)

func (w *x86mcw) swiol(iol interface{}) {
	switch v := iol.(type){
		case int:
			w.m.Write(Bin32L(v))
		case string:
			w.m.WrlabVA(v)
		default:
			fmt.Println("Error: ", iol)
			os.Exit(1)
	}
}

func (w *x86mcw) MovRegNum(dst uint16, src interface{}) {
	w.m.Write(Bin8(184 | dst))
	w.swiol(src)
}

func (w *x86mcw) MovRegPtr(dst uint16, src interface{}, byteSrc uint8) {
	if dst == EAX {
		w.m.Write(Bin8(161))
	}else{
		w.m.Write(Bin16L(1419 | dst << 11)) // de10110001011
	}
	w.swiol(src)
}

func (w *x86mcw) MovRegReg(dst uint16, src uint16) {
	w.m.Write(Bin16L(49289 | src << 11 | dst << 8)) // 110sr0de10001001
}

func (w *x86mcw) PushReg(src uint16) {
	w.m.Write(Bin8(80 | src))
}

func (w *x86mcw) Pop(dst uint16) {
	w.m.Write(Bin8(88 | dst))
}

func (w *x86mcw) CallReg(dst uint16) {
	w.m.Write(Bin16L(53503 | dst << 8)) // 110100RG11111111
}
