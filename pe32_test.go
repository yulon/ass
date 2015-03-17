package ass

import (
	"testing"
)

func Test_PE32(t *testing.T) {
	exe, _ := NewPEMaker("pe32_test.exe")
	exe.WriteDOSHeader()
	exe.WriteNTHeader()
	exe.WriteSectionHeader()
	exe.SectionStart()
	exe.Import("kernel32.dll", "ExitProcess")
	exe.Import("msvcrt.dll", "printf")
	exe.WriteSpace(100)
	exe.WriteImportDescriptors()
	exe.SectionEnd()
	exe.Close()
}