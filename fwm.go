package ass

import (
	"os"
	"errors"
	"fmt"
)

type fileWriteManager struct{
	*os.File
	labels map[string]int64
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

func newFileWriteManager(f *os.File) *fileWriteManager {
	fwm := &fileWriteManager{
		File: f,
		labels: map[string]int64{},
		pits: []pit{},
	}
	fwm.start = fwm.Len()
	return fwm
}

func (fwm *fileWriteManager) Label(l string) {
	fwm.labels[l] = fwm.Len()
}

func (fwm *fileWriteManager) Len() int64 {
	fi, err := fwm.Stat()
	if err != nil {
		return 0
	}
	return int64(fi.Size())
}

func (fwm *fileWriteManager) PitOffset(startLabel string, endLabel string, added int64, numPut NumPut) {
	fwm.pits = append(fwm.pits, pit{
		addr: fwm.Len(),
		start: startLabel,
		end: endLabel,
		added: added,
		numPut: numPut,
	})
	switch fmt.Sprint(numPut) {
		case fmt.Sprint(Num8):
			fwm.Write(Zeros(1))
		case fmt.Sprint(Num16L):
			fwm.Write(Zeros(2))
		case fmt.Sprint(Num32L):
			fwm.Write(Zeros(4))
		case fmt.Sprint(Num64L):
			fwm.Write(Zeros(8))
		case fmt.Sprint(Num16B):
			fwm.Write(Zeros(2))
		case fmt.Sprint(Num32B):
			fwm.Write(Zeros(4))
		case fmt.Sprint(Num64B):
			fwm.Write(Zeros(8))
	}
}

func (fwm *fileWriteManager) PitPointer(label string, numPut NumPut) {
	fwm.PitOffset("", label, 0, numPut)
}

func (fwm *fileWriteManager) PitRelative(label string, numPut NumPut) {
	fwm.PitOffset(label, "", 0, numPut)
}

func (fwm *fileWriteManager) Close() error {
	for i := 0; i < len(fwm.pits); i++ {
		var start, end int64
		var ok bool

		if fwm.pits[i].start == "" {
			start = fwm.start
		}else{
			start, ok = fwm.labels[fwm.pits[i].start]
			if !ok {
				return errors.New(fwm.pits[i].start + " is not found")
			}
		}

		if fwm.pits[i].end == "" {
			end = fwm.pits[i].addr
		}else{
			end, ok = fwm.labels[fwm.pits[i].end]
			if !ok {
				return errors.New(fwm.pits[i].end + " is not found")
			}
		}

		n := end - start + fwm.pits[i].added
		fwm.WriteAt(fwm.pits[i].numPut(n), fwm.pits[i].addr)
	}
	return nil
}
