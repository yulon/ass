package ass

import (
	"testing"
	"fmt"
)

func Test_PE32(t *testing.T) {
	exe, _ := CreatePE("test32.exe", MACHINE_X86, PE_IMAGEBASE_GENERAL, true)

	exe.Write([]byte{104}) // push _
	exe.WriteVA("hw", Bit32)

	exe.Write([]byte{255, 21}) // call [_]
	exe.WriteDLLFuncPtr("msvcrt.dll", "printf")

	exe.Write([]byte{255, 21}) // call [_]
	exe.WriteDLLFuncPtr("kernel32.dll", "ExitProcess")

	exe.Label("hw")
	exe.Write("Hello, World!\r\n")
	exe.Write(byte(0))

	fmt.Println(exe.Close())
}

func Test_PE64(t *testing.T) {
	exe, _ := CreatePE("test64.exe", MACHINE_X64, PE_IMAGEBASE_GENERAL, true)

	exe.Write([]byte{72, 185});  // mov rcx, _
	exe.WriteVA("hw", Bit64)

	exe.Write([]byte{255, 20, 37}) // call [_]
	exe.WriteDLLFuncPtr("msvcrt.dll", "printf")

	exe.Write([]byte{255, 20, 37}) // call [_]
	exe.WriteDLLFuncPtr("kernel32.dll", "ExitProcess")

	exe.Label("hw")
	exe.Write("Hello, World!\r\n")
	exe.Write(byte(0))

	fmt.Println(exe.Close())
}