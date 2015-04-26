package ass

import (
	"testing"
	"fmt"
	//"strconv"
)

func TestPE32(*testing.T) {
	exe, _ := CreatePE("test32.exe", I386, PE_IMAGEBASE_GENERAL, true)

	exe.MovRegImm(EAX, "hw_string")
	exe.PushReg(EAX)

	exe.MovRegMem(EAX, exe.DLLFuncPtr("msvcrt.dll", "printf"), 4)
	exe.CallReg(EAX)

	exe.MovRegMem(EAX, exe.DLLFuncPtr("kernel32.dll", "ExitProcess"), 8)
	exe.CallReg(EAX)

	exe.Label("hw_string")
	exe.Write(Chars("Hello, World!\r\n"))

	fmt.Println(exe.Close())
}

func TestPE64(*testing.T) {
	exe, _ := CreatePE("test64.exe", AMD64, PE_IMAGEBASE_GENERAL, true)

	exe.Write([]byte{72, 184})
	exe.WrlabVA("hw_string", BinNum64L)
	exe.Write([]byte{72, 137, 193})

	exe.Write([]byte{72, 184})
	exe.WrlabVA(exe.DLLFuncPtr("msvcrt.dll", "printf"), BinNum64L)
	exe.Write([]byte{72, 139, 00})
	exe.Write([]byte{255, 208})

	exe.Write([]byte{72, 184})
	exe.WrlabVA(exe.DLLFuncPtr("kernel32.dll", "ExitProcess"), BinNum64L)
	exe.Write([]byte{72, 139, 00})
	exe.Write([]byte{255, 208})

	exe.Label("hw_string")
	exe.Write(Chars("Hello, World!\r\n"))

	fmt.Println(exe.Close())
}
