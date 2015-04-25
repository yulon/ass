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

	exe.Ins("push", "dword", "hw_string")
	exe.Ins("call", "ptr", exe.ImpDLLFnPtr("msvcrt.dll", "printf"))

	exe.Ins("call", "ptr", exe.ImpDLLFnPtr("kernel32.dll", "ExitProcess"))


	exe.Label("hw_string")
	exe.Write("Hello, World!\r\n")
	exe.Write(byte(0))

	fmt.Println(exe.Close())
}
