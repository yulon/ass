package ass

import (
	"testing"
	"fmt"
)

func Test_PE32(t *testing.T) {
	exe, _ := CreatePE("test_pe32.exe", MACHINE_X86, PE_IMAGEBASE_GENERAL, true)

	exe.ImpBinLibFunc("kernel32.dll", "ExitProcess")
	exe.ImpBinLibFunc("msvcrt.dll", "printf")

	exe.Write([]byte{104}) // PUSH
	exe.WriteVA("hw", Bit32)

	exe.Write([]byte{255, 21}) // CALL PTR
	exe.WriteBinlibFuncPtr("printf")

	exe.Write([]byte{255, 21}) // CALL PTR
	exe.WriteBinlibFuncPtr("ExitProcess")

	exe.Label("hw")
	exe.Write("Hello, World!\r\n")
	exe.Write(byte(0))

	fmt.Println(exe.Close())
}

func Test_PE64(t *testing.T) {
	exe, _ := CreatePE("test_pe64.exe", MACHINE_X64, PE_IMAGEBASE_GENERAL, true)

	exe.ImpBinLibFunc("kernel32.dll", "ExitProcess")
	exe.ImpBinLibFunc("msvcrt.dll", "printf")

	fmt.Println(exe.Close())
}