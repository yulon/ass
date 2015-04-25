package ass

import (
	"testing"
	"fmt"
	"strconv"
)

func Test_PE(t *testing.T) {
	hw_exe(X86)
	//hw_exe(X64)
}

func hw_exe(machine int) {
	exe, _ := CreatePE("test" + strconv.Itoa(machine * 8) + ".exe", machine, PE_IMAGEBASE_GENERAL, true)

	exe.Ins.MovRegNum("eax", nil)
	exe.WrlabVA("hw_string")
	exe.Ins.Push("eax")

	exe.Ins.MovRegPtr("eax", nil)
	exe.WriteDLLFnPtr("msvcrt.dll", "printf")
	exe.Ins.CallReg("eax")

	exe.Ins.MovRegPtr("eax", nil)
	exe.WriteDLLFnPtr("kernel32.dll", "ExitProcess")
	exe.Ins.CallReg("eax")

	exe.Label("hw_string")
	exe.Write("Hello, World!\r\n")
	exe.Write(byte(0))

	fmt.Println(exe.Close())
}
