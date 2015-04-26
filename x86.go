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
	ooReg = 3 //11
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

func (w *x86mcw) MovRegNum(dst int, src interface{}) {
	w.m.Write(Bin8(184 | dst))
	w.swiol(src)
}

func (w *x86mcw) MovRegPtr(dst int, src interface{}, byteSrc uint8) {
	if dst == EAX {
		w.m.Write(Bin8(161))
	}else{
		w.m.Write(Bin16B(35613 | dst << 3)) //1000101woorrrmmm w=1 oo=00 rrr=dst mmm=101
	}
	w.swiol(src)
}

func (w *x86mcw) MovRegReg(dst int, src int) {
	w.m.Write(Bin16B(35776 | ooReg << 6 | dst << 3 | src)) //1000101woorrrmmm w=1 oo=ooReg rrr=dst mmm=src
}

func (w *x86mcw) PushReg(src int) {
	w.m.Write(Bin8(80 | src))
}

func (w *x86mcw) Pop(dst int) {
	w.m.Write(Bin8(88 | dst))
}

func (w *x86mcw) CallReg(dst int) {
	w.m.Write(Bin16B(65488 | ooReg << 6 | dst)) //11111111oo010mmm oo=ooReg mmm=dst
}
