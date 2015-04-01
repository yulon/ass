package ass

import (
	"testing"
	"fmt"
	"strconv"
)

func Test_PE(t *testing.T) {
	hw_exe(MACHINE_X86)
	hw_exe(MACHINE_X64)
}

func hw_exe(machine int) {
	exe, _ := CreatePE("test" + strconv.Itoa(machine) + ".exe", machine, PE_IMAGEBASE_GENERAL, true)

	exe.Reg()
	exe.WriteVA("hw_string")
	exe.Sep()

	exe.Reg()
	exe.WriteDLLFuncPtr("msvcrt.dll", "printf")
	exe.Adi()
	exe.Cal()

	exe.Reg()
	exe.WriteDLLFuncPtr("kernel32.dll", "ExitProcess")
	exe.Adi()
	exe.Cal()

	exe.Label("hw_string")
	exe.Write("Hello, World!\r\n")
	exe.Write(byte(0))

	fmt.Println(exe.Close())
}