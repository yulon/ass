package ass

import (
	"testing"
)

func Test_PE32(t *testing.T) {
	exe, _ := NewPEMaker("pe32_test.exe", CPU_X86, PE_IMAGEBASE_GENERAL, true)
	exe.Import("kernel32.dll", "ExitProcess")
	exe.Import("msvcrt.dll", "printf")
	exe.WriteSpace(100)
	exe.Close()
}