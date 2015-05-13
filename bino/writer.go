package bino

import "io"

type Writer struct{
	w io.Writer
}

func NewWriter(w io.Writer) *Writer {
	return &Writer{w}
}

func (w *Writer) Byte(data interface{}) (int, error) {
	return w.w.Write(Byte(data))
}

func (w *Writer) Word(data interface{}) (int, error) {
	return w.w.Write(Word(data))
}

func (w *Writer) Dword(data interface{}) (int, error) {
	return w.w.Write(Dword(data))
}

func (w *Writer) Qword(data interface{}) (int, error) {
	return w.w.Write(Qword(data))
}

func (w *Writer) WordB(data interface{}) (int, error) {
	return w.w.Write(WordB(data))
}

func (w *Writer) DwordB(data interface{}) (int, error) {
	return w.w.Write(DwordB(data))
}

func (w *Writer) QwordB(data interface{}) (int, error) {
	return w.w.Write(QwordB(data))
}

func (w *Writer) Cstr(text string) (int, error) {
	return w.w.Write(append([]byte(text), 0))
}

func (w *Writer) Zeros(size int64) (int, error) {
	return w.w.Write(make([]byte, size, size))
}
