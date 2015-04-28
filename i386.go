package ass

import (
	"io"
	"fmt"
)

const I386 = 4

type i386QW struct{
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

func (qw *i386QW) Close() error {
	return qw.l.Close()
}

func (qw *i386QW) switchW(infa interface{}, nbo NumBitOrder) {
	switch v := infa.(type){
		case int:
			qw.Write(nbo(v))
		case func(NumBitOrder):
			v(nbo)
		default:
			fmt.Println("Error: ", infa)
	}
}

func (qw *i386QW) MovRegImm(dst int, src interface{}) {
	qw.Write(Num8(184 | dst)) //1011wrrr w=1 rrr=dst
	qw.switchW(src, Num32L)
}

func (qw *i386QW) MovRegMem(dst int, src interface{}, byteSrc uint8) {
	if dst == EAX {
		qw.Write(Num8(161))
	}else{
		qw.Write(Num16B(35613 | dst << 3)) //1000101woorrrmmm w=1 oo=00 rrr=dst mmm=101
	}
	qw.switchW(src, Num32L)
}

func (qw *i386QW) MovRegReg(dst int, src int) {
	qw.Write(Num16B(35776 | ooReg << 6 | dst << 3 | src)) //1000101woorrrmmm w=1 oo=ooReg rrr=dst mmm=src
}

func (qw *i386QW) PushReg(src int) {
	qw.Write(Num8(80 | src))
}

func (qw *i386QW) Pop(dst int) {
	qw.Write(Num8(88 | dst))
}

func (qw *i386QW) CallReg(dst int) {
	qw.Write(Num16B(65488 | ooReg << 6 | dst)) //11111111oo010mmm oo=ooReg mmm=dst
}
