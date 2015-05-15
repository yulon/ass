package ass

import (
	"io"
	"fmt"
	"github.com/yulon/go-octrl"
	"github.com/yulon/go-bin"
)

type I386Writer struct{
	b *bin.Writer
	l *octrl.Labeler
	bva int64
}

func NewI386Writer(ws io.WriteSeeker, BaseVA int64) *I386Writer {
	return &I386Writer{
		b: bin.NewWriter(ws),
		l: octrl.NewLabeler(ws),
		bva: BaseVA,
	}
}

const (
	EAX = 0 // 000
	EBX = 3 // 011
	ECX = 1 // 001
	EDX = 2 // 010
	ESI = 6 // 110
	EDI = 7 // 111
	EBP = 5 // 101
	ESP = 4 // 100
	ooReg = 3 // 11
)

func (w *I386Writer) Label(l string) {
	w.l.Label(l)
}

func (w *I386Writer) Close() error {
	return w.l.Close()
}

func (w *I386Writer) switchW(infa interface{}, conv bin.Converter) {
	switch v := infa.(type){
		case int:
			w.b.Write(conv(v))
		case func(bin.Converter):
			v(conv)
		default:
			fmt.Println("Error: ", infa)
	}
}

func (w *I386Writer) MovRegImm(dst int, src interface{}) {
	w.b.Byte(184 | dst) // 1011wrrr w=1 rrr=dst
	w.switchW(src, bin.Dword)
}

func (w *I386Writer) MovRegMem(dst int, src interface{}, byteSrc uint8) {
	if dst == EAX {
		w.b.Byte(161)
	}else{
		w.b.WordB(35613 | dst << 3) // 1000101woorrrmmm w=1 oo=00 rrr=dst mmm=101
	}
	w.switchW(src, bin.Dword)
}

func (w *I386Writer) MovRegReg(dst int, src int) {
	w.b.WordB(35776 | ooReg << 6 | dst << 3 | src) // 1000101woorrrmmm w=1 oo=ooReg rrr=dst mmm=src
}

func (w *I386Writer) PushReg(src int) {
	w.b.Byte(80 | src)
}

func (w *I386Writer) Pop(dst int) {
	w.b.Byte(88 | dst)
}

func (w *I386Writer) CallReg(dst int) {
	w.b.WordB(65488 | ooReg << 6 | dst) // 11111111oo010mmm oo=ooReg mmm=dst
}

func (w *I386Writer) Lock() { // ADD, ADC, AND, BTC, BTR, BTS, CMPXCHG, CMPXCH8B, DEC, INC, NEG, NOT, OR, SBB, SUB, XOR, XADD, XCHG
	w.b.Byte(240)
}
