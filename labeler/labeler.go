package labeler

import (
	"io"
	"errors"
	"github.com/yulon/ass/bin"
)

type Writer struct{
	ws io.WriteSeeker
	labs map[string]int64
	pits []pit
	base int64
}

type pit struct{
	addr int64
	start string
	end string
	added int64
	ic bin.IntConv
}

func New(ws io.WriteSeeker) *Writer {
	offset, err := ws.Seek(0, 1)
	if err != nil {
		return nil
	}

	w := &Writer{
		ws: ws,
		labs: map[string]int64{},
		pits: []pit{},
		base: offset,
	}
	return w
}

func (w *Writer) Label(l string) error {
	offset, err := w.ws.Seek(0, 1)
	if err != nil {
		return err
	}

	w.labs[l] = offset
	return nil
}

func (w *Writer) Pit(startLabel string, endLabel string, added int64, ic bin.IntConv) (int, error) {
	addr, err := w.ws.Seek(0, 1)
	if err != nil {
		return 0, err
	}

	w.pits = append(w.pits, pit{
		addr: addr,
		start: startLabel,
		end: endLabel,
		added: added,
		ic: ic,
	})
	return w.ws.Write(ic(0))
}

func (w *Writer) Close() error {
	current, err := w.ws.Seek(0, 1)
	if err != nil {
		return err
	}

	for i := 0; i < len(w.pits); i++ {
		var start, end int64
		var ok bool

		if w.pits[i].start == "" {
			start = w.base
		}else{
			start, ok = w.labs[w.pits[i].start]
			if !ok {
				return errors.New(w.pits[i].start + " is not found")
			}
		}

		if w.pits[i].end == "" {
			end = w.pits[i].addr
		}else{
			end, ok = w.labs[w.pits[i].end]
			if !ok {
				return errors.New(w.pits[i].end + " is not found")
			}
		}

		n := end - start + w.pits[i].added

		_, err = w.ws.Seek(w.pits[i].addr, 0)
		if err != nil {
			return err
		}

		w.ws.Write(w.pits[i].ic(n))
	}

	_, err = w.ws.Seek(current, 0)
	return err
}
