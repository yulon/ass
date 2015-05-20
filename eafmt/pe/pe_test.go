package pe

import (
	"testing"
	//"fmt"
	//"strconv"
	"github.com/yulon/go-ass"
	"github.com/yulon/go-bin"
)

func TestPE32(*testing.T) {
	exe, _ := Create("test32.exe", IMAGE_FILE_MACHINE_I386, 0x00400000, false)
	code := ass.NewI386(exe, exe.GetVA())

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
	exe, _ := Create("test64.exe", IMAGE_FILE_MACHINE_AMD64, 0x00400000, false)

	exe.Write([]byte{72, 184})
	exe.Data(bin.Cstr("Hello, World!\r\n"))(bin.Qword)
	exe.Write([]byte{72, 137, 193})

	exe.Write([]byte{72, 184})
	exe.DLLFuncPtr("msvcrt.dll", "printf")(bin.Qword)
	exe.Write([]byte{72, 139, 00})
	exe.Write([]byte{255, 208})

	exe.Write([]byte{72, 184})
	exe.DLLFuncPtr("kernel32.dll", "ExitProcess")(bin.Qword)
	exe.Write([]byte{72, 139, 00})
	exe.Write([]byte{255, 208})

	exe.Close()
}
