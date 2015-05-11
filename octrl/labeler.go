package octrl

import (
	"io"
	"errors"
	"github.com/yulon/go-ass/bin"
)

type Labeler struct{
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

func NewLabeler(ws io.WriteSeeker) *Labeler {
	offset, err := ws.Seek(0, 1)
	if err != nil {
		return nil
	}

	laber := &Labeler{
		ws: ws,
		labs: map[string]int64{},
		pits: []pit{},
		base: offset,
	}
	return laber
}

func (laber *Labeler) Label(l string) error {
	offset, err := laber.ws.Seek(0, 1)
	if err != nil {
		return err
	}

	laber.labs[l] = offset
	return nil
}

func (laber *Labeler) Pit(startLabel string, endLabel string, added int64, ic bin.IntConv) (int, error) {
	addr, err := laber.ws.Seek(0, 1)
	if err != nil {
		return 0, err
	}

	laber.pits = append(laber.pits, pit{
		addr: addr,
		start: startLabel,
		end: endLabel,
		added: added,
		ic: ic,
	})
	return laber.ws.Write(ic(0))
}

func (laber *Labeler) Close() error {
	current, err := laber.ws.Seek(0, 1)
	if err != nil {
		return err
	}

	for i := 0; i < len(laber.pits); i++ {
		var start, end int64
		var ok bool

		if laber.pits[i].start == "" {
			start = laber.base
		}else{
			start, ok = laber.labs[laber.pits[i].start]
			if !ok {
				return errors.New(laber.pits[i].start + " is not found")
			}
		}

		if laber.pits[i].end == "" {
			end = laber.pits[i].addr
		}else{
			end, ok = laber.labs[laber.pits[i].end]
			if !ok {
				return errors.New(laber.pits[i].end + " is not found")
			}
		}

		n := end - start + laber.pits[i].added

		_, err = laber.ws.Seek(laber.pits[i].addr, 0)
		if err != nil {
			return err
		}

		laber.ws.Write(laber.pits[i].ic(n))
	}

	_, err = laber.ws.Seek(current, 0)
	return err
}
