package ass

import (
	"io"
	"fmt"
)

const I386 = 4

type i386 struct{
	io.Writer
	l *labeler
	base int64
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

func (w *i386) Label(l string) {
	w.l.Label(l)
}

func (w *i386) Close() error {
	return w.l.Close()
}

func (w *i386) switchW(infa interface{}, nbo NumBitOrder) {
	switch v := infa.(type){
		case int:
			w.Write(nbo(v))
		case func(NumBitOrder):
			v(nbo)
		default:
			fmt.Println("Error: ", infa)
	}
}

func (w *i386) MovRegImm(dst int, src interface{}) {
	w.Write(Num8(184 | dst)) //1011wrrr w=1 rrr=dst
	w.switchW(src, Num32L)
}

func (w *i386) MovRegMem(dst int, src interface{}, byteSrc uint8) {
	if dst == EAX {
		w.Write(Num8(161))
	}else{
		w.Write(Num16B(35613 | dst << 3)) //1000101woorrrmmm w=1 oo=00 rrr=dst mmm=101
	}
	w.switchW(src, Num32L)
}

func (w *i386) MovRegReg(dst int, src int) {
	w.Write(Num16B(35776 | ooReg << 6 | dst << 3 | src)) //1000101woorrrmmm w=1 oo=ooReg rrr=dst mmm=src
}

func (w *i386) PushReg(src int) {
	w.Write(Num8(80 | src))
}

func (w *i386) Pop(dst int) {
	w.Write(Num8(88 | dst))
}

func (w *i386) CallReg(dst int) {
	w.Write(Num16B(65488 | ooReg << 6 | dst)) //11111111oo010mmm oo=ooReg mmm=dst
}
