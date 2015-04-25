package ass

import (
	"testing"
	"fmt"
	"strconv"
)

func Test_PE(t *testing.T) {
	hw_exe(MACHINE_X86)
	//hw_exe(MACHINE_X64)
}

func hw_exe(machine int) {
	exe, _ := CreatePE("test" + strconv.Itoa(machine * 8) + ".exe", machine, PE_IMAGEBASE_GENERAL, true)

	exe.MovRegNum("eax", "hw_string")
	exe.PushReg("eax")

	exe.MovRegPtr("eax", exe.ImpDLLFnPtr("msvcrt.dll", "printf"), Bit32)
	exe.CallReg("eax")

	exe.MovRegPtr("eax", exe.ImpDLLFnPtr("kernel32.dll", "ExitProcess"), Bit32)
	exe.CallReg("eax")


	exe.Label("hw_string")
	exe.Write("Hello, World!\r\n")
	exe.Write(byte(0))

	fmt.Println(exe.Close())
}
