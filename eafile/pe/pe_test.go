package pe

import (
	"testing"
	//"fmt"
	//"strconv"
	"github.com/yulon/go-ass"
	"github.com/yulon/go-bin"
)

func TestPE32(*testing.T) {
	exe, _ := Create("test32.exe", I386, PE_IMAGEBASE_GENERAL, true)
	code := ass.NewI386(exe.f, PE_IMAGEBASE_GENERAL)

	code.MovRegImm(ass.EAX, exe.Data(bin.Cstr("Hello, World!\r\n")))
	code.PushReg(ass.EAX)

	code.MovRegMem(ass.EAX, exe.DLLFuncPtr("msvcrt.dll", "printf"), 4)
	code.CallReg(ass.EAX)

	code.MovRegMem(ass.EAX, exe.DLLFuncPtr("kernel32.dll", "ExitProcess"), 4)
	code.CallReg(ass.EAX)

	code.Close()
	exe.Close()
}

func TestPE64(*testing.T) {
	exe, _ := Create("test64.exe", AMD64, PE_IMAGEBASE_GENERAL, true)

	exe.f.Write([]byte{72, 184})
	exe.Data(bin.Cstr("Hello, World!\r\n"))(bin.Qword)
	exe.f.Write([]byte{72, 137, 193})

	exe.f.Write([]byte{72, 184})
	exe.DLLFuncPtr("msvcrt.dll", "printf")(bin.Qword)
	exe.f.Write([]byte{72, 139, 00})
	exe.f.Write([]byte{255, 208})

	exe.f.Write([]byte{72, 184})
	exe.DLLFuncPtr("kernel32.dll", "ExitProcess")(bin.Qword)
	exe.f.Write([]byte{72, 139, 00})
	exe.f.Write([]byte{255, 208})

	exe.writeImportDescriptors()
	exe.writeDatas()
	exe.sectionEnd()
	exe.l.Close()
	exe.f.Close()
}
