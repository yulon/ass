package ass

import (
	"testing"
	//"fmt"
	//"strconv"
)

func TestPE32(*testing.T) {
	exe, _ := CreatePE("test32.exe", I386, PE_IMAGEBASE_GENERAL, true)

	exe.MovRegImm(EAX, exe.Data(Chars("Hello, World!\r\n")))
	exe.PushReg(EAX)

	exe.MovRegMem(EAX, exe.DLLFuncPtr("msvcrt.dll", "printf"), 4)
	exe.CallReg(EAX)

	exe.MovRegMem(EAX, exe.DLLFuncPtr("kernel32.dll", "ExitProcess"), 4)
	exe.CallReg(EAX)

	exe.Close()
}

func TestPE64(*testing.T) {
	exe, _ := CreatePE("test64.exe", AMD64, PE_IMAGEBASE_GENERAL, true)

	exe.f.Write([]byte{72, 184})
	exe.Data(Chars("Hello, World!\r\n"))(Num64L)
	exe.f.Write([]byte{72, 137, 193})

	exe.f.Write([]byte{72, 184})
	exe.DLLFuncPtr("msvcrt.dll", "printf")(Num64L)
	exe.f.Write([]byte{72, 139, 00})
	exe.f.Write([]byte{255, 208})

	exe.f.Write([]byte{72, 184})
	exe.DLLFuncPtr("kernel32.dll", "ExitProcess")(Num64L)
	exe.f.Write([]byte{72, 139, 00})
	exe.f.Write([]byte{255, 208})

	exe.writeImportDescriptors()
	exe.writeDatas()
	exe.sectionEnd()
	exe.l.Close()
	exe.f.Close()
}
