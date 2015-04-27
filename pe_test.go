package ass

import (
	"testing"
	"fmt"
	//"strconv"
)

func TestPE32(*testing.T) {
	exe, _ := CreatePE("test32.exe", I386, PE_IMAGEBASE_GENERAL, true)

	exe.MovRegImm(EAX, func(numPut NumPut){
		exe.pitVA("hw_string", numPut)
	})

	exe.PushReg(EAX)

	exe.MovRegMem(EAX, func(numPut NumPut){
		exe.pitVA(exe.DLLFuncPtr("msvcrt.dll", "printf"), numPut)
	}, 4)
	exe.CallReg(EAX)

	exe.MovRegMem(EAX, func(numPut NumPut){
		exe.pitVA(exe.DLLFuncPtr("kernel32.dll", "ExitProcess"), numPut)
	}, 4)
	exe.CallReg(EAX)

	exe.fwm.Label("hw_string")
	exe.Write(Chars("Hello, World!\r\n"))

	fmt.Println(exe.Close())
}

func TestPE64(*testing.T) {
	exe, _ := CreatePE("test64.exe", AMD64, PE_IMAGEBASE_GENERAL, true)

	exe.Write([]byte{72, 184})
	exe.pitVA("hw_string", Num64L)
	exe.Write([]byte{72, 137, 193})

	exe.Write([]byte{72, 184})
	exe.pitVA(exe.DLLFuncPtr("msvcrt.dll", "printf"), Num64L)
	exe.Write([]byte{72, 139, 00})
	exe.Write([]byte{255, 208})

	exe.Write([]byte{72, 184})
	exe.pitVA(exe.DLLFuncPtr("kernel32.dll", "ExitProcess"), Num64L)
	exe.Write([]byte{72, 139, 00})
	exe.Write([]byte{255, 208})

	exe.fwm.Label("hw_string")
	exe.Write(Chars("Hello, World!\r\n"))

	fmt.Println(exe.Close())
}
