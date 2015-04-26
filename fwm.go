package ass

import (
	"os"
	"bytes"
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
	bnt BinNumTranslator
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

func (fwm *fileWriteManager) WriteSpace(count int) {
	fwm.Write(bytes.Repeat([]byte{0}, count))
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

func (fwm *fileWriteManager) WrlabOffset(startLabel string, endLabel string, added int64, bnt BinNumTranslator) {
	fwm.pits = append(fwm.pits, pit{
		addr: fwm.Len(),
		start: startLabel,
		end: endLabel,
		added: added,
		bnt: bnt,
	})
	switch fmt.Sprint(bnt) {
		case fmt.Sprint(BinNum8):
			fwm.WriteSpace(1)
		case fmt.Sprint(BinNum16L):
			fwm.WriteSpace(2)
		case fmt.Sprint(BinNum32L):
			fwm.WriteSpace(4)
		case fmt.Sprint(BinNum64L):
			fwm.WriteSpace(8)
		case fmt.Sprint(BinNum16B):
			fwm.WriteSpace(2)
		case fmt.Sprint(BinNum32B):
			fwm.WriteSpace(4)
		case fmt.Sprint(BinNum64B):
			fwm.WriteSpace(8)
	}
}

func (fwm *fileWriteManager) WrlabPointer(label string, bnt BinNumTranslator) {
	fwm.WrlabOffset("", label, 0, bnt)
}

func (fwm *fileWriteManager) WrlabRelative(label string, bnt BinNumTranslator) {
	fwm.WrlabOffset(label, "", 0, bnt)
}

func (fwm *fileWriteManager) Fill() error {
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
		fwm.WriteAt(fwm.pits[i].bnt(n), fwm.pits[i].addr)
	}
	return nil
}
