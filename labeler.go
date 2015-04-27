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
	numPut NumPut
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

func (laber *labeler) PitOffset(startLabel string, endLabel string, added int64, numPut NumPut) {
	laber.pits = append(laber.pits, pit{
		addr: fSize(laber.f),
		start: startLabel,
		end: endLabel,
		added: added,
		numPut: numPut,
	})
	switch fmt.Sprint(numPut) {
		case fmt.Sprint(Num8):
			laber.f.Write(Zeros(1))
		case fmt.Sprint(Num16L):
			laber.f.Write(Zeros(2))
		case fmt.Sprint(Num32L):
			laber.f.Write(Zeros(4))
		case fmt.Sprint(Num64L):
			laber.f.Write(Zeros(8))
		case fmt.Sprint(Num16B):
			laber.f.Write(Zeros(2))
		case fmt.Sprint(Num32B):
			laber.f.Write(Zeros(4))
		case fmt.Sprint(Num64B):
			laber.f.Write(Zeros(8))
	}
}

func (laber *labeler) PitPointer(label string, numPut NumPut) {
	laber.PitOffset("", label, 0, numPut)
}

func (laber *labeler) PitRelative(label string, numPut NumPut) {
	laber.PitOffset(label, "", 0, numPut)
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
		laber.f.WriteAt(laber.pits[i].numPut(n), laber.pits[i].addr)
	}
	return nil
}
