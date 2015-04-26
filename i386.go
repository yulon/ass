package ass

import (
	"os"
	"fmt"
)

const I386 = 4

type i386 struct{
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

func (w *i386) swiol(iol interface{}, bnt BinNumTranslator) {
	switch v := iol.(type){
		case int:
			w.m.Write(bnt(v))
		case string:
			w.m.WrlabVA(v, bnt)
		default:
			fmt.Println("Error: ", iol)
			os.Exit(1)
	}
}

func (w *i386) MovRegImm(dst int, src interface{}) {
	w.m.Write(BinNum8(184 | dst)) //1011wrrr w=1 rrr=dst
	w.swiol(src, BinNum32L)
}

func (w *i386) MovRegMem(dst int, src interface{}, byteSrc uint8) {
	if dst == EAX {
		w.m.Write(BinNum8(161))
	}else{
		w.m.Write(BinNum16B(35613 | dst << 3)) //1000101woorrrmmm w=1 oo=00 rrr=dst mmm=101
	}
	w.swiol(src, BinNum32L)
}

func (w *i386) MovRegReg(dst int, src int) {
	w.m.Write(BinNum16B(35776 | ooReg << 6 | dst << 3 | src)) //1000101woorrrmmm w=1 oo=ooReg rrr=dst mmm=src
}

func (w *i386) PushReg(src int) {
	w.m.Write(BinNum8(80 | src))
}

func (w *i386) Pop(dst int) {
	w.m.Write(BinNum8(88 | dst))
}

func (w *i386) CallReg(dst int) {
	w.m.Write(BinNum16B(65488 | ooReg << 6 | dst)) //11111111oo010mmm oo=ooReg mmm=dst
}
