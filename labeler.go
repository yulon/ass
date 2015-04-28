package ass

import (
	"os"
	"errors"
	"fmt"
)

type labeler struct{
	f *os.File
	labs map[string]int64
	pits []pit
	start int64
}

type pit struct{
	addr int64
	start string
	end string
	added int64
	nbo NumBitOrder
}

func newLabeler(file *os.File) *labeler {
	laber := &labeler{
		f: file,
		labs: map[string]int64{},
		pits: []pit{},
	}
	laber.start = fSize(laber.f)
	return laber
}

func (laber *labeler) Label(l string) {
	laber.labs[l] = fSize(laber.f)
}

func (laber *labeler) PitOffset(startLabel string, endLabel string, added int64, nbo NumBitOrder) {
	laber.pits = append(laber.pits, pit{
		addr: fSize(laber.f),
		start: startLabel,
		end: endLabel,
		added: added,
		nbo: nbo,
	})
	switch fmt.Sprint(nbo) {
		case nboNum8:
			laber.f.Write(Zeros(1))
		case nboNum16L:
			laber.f.Write(Zeros(2))
		case nboNum32L:
			laber.f.Write(Zeros(4))
		case nboNum64L:
			laber.f.Write(Zeros(8))
		case nboNum16B:
			laber.f.Write(Zeros(2))
		case nboNum32B:
			laber.f.Write(Zeros(4))
		case nboNum64B:
			laber.f.Write(Zeros(8))
	}
}

func (laber *labeler) PitPointer(label string, nbo NumBitOrder) {
	laber.PitOffset("", label, 0, nbo)
}

func (laber *labeler) PitRelative(label string, nbo NumBitOrder) {
	laber.PitOffset(label, "", 0, nbo)
}

func (laber *labeler) Close() error {
	for i := 0; i < len(laber.pits); i++ {
		var start, end int64
		var ok bool

		if laber.pits[i].start == "" {
			start = laber.start
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
		laber.f.WriteAt(laber.pits[i].nbo(n), laber.pits[i].addr)
	}
	return nil
}
