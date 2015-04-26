package ass

import (
	"testing"
	"fmt"
	//"strconv"
)

func TestPE32(*testing.T) {
	exe, _ := CreatePE("test32.exe", MACHINE_X86, PE_IMAGEBASE_GENERAL, true)

	exe.MovRegImm(EAX, "hw_string")
	exe.PushReg(EAX)

	exe.MovRegMem(EAX, exe.DLLFnPtr("msvcrt.dll", "printf"), 4)
	exe.CallReg(EAX)

	exe.MovRegMem(EAX, exe.DLLFnPtr("kernel32.dll", "ExitProcess"), 8)
	exe.CallReg(EAX)

	exe.Label("hw_string")
	exe.Write(Chars("Hello, World!\r\n"))

	fmt.Println(exe.Close())
}

func TestPE64(*testing.T) {
	exe, _ := CreatePE("test64.exe", MACHINE_X64, PE_IMAGEBASE_GENERAL, true)

	exe.Write([]byte{72, 184})
	exe.WrlabVA("hw_string")
	exe.Write([]byte{72, 137, 193})

	exe.Write([]byte{72, 184})
	exe.WrlabVA(exe.DLLFnPtr("msvcrt.dll", "printf"))
	exe.Write([]byte{72, 139, 00})
	exe.Write([]byte{255, 208})

	exe.Write([]byte{72, 184})
	exe.WrlabVA(exe.DLLFnPtr("kernel32.dll", "ExitProcess"))
	exe.Write([]byte{72, 139, 00})
	exe.Write([]byte{255, 208})

	exe.Label("hw_string")
	exe.Write(Chars("Hello, World!\r\n"))

	fmt.Println(exe.Close())
}
