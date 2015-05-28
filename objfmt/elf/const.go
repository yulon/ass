package elf

const (
	et_NONE = 0 // No file type
	et_REL = 1 // Relocatable file
	et_EXEC = 2 // Executable file
	et_DYN = 3 // Shared object file
	et_CORE = 4 // Core file
	et_LOPROC = 0xff00 // Processor-specific
	et_HIPROC = 0xffff // Processor-specific
	em_386 = 3 // Intel 80386
	shn_UNDEF = 0
	CLASS32 = 1 // 32-bit objects
	CLASS64 = 2 // 64-bit objects
	ev_CURRENT = 1
	DATA2LSB = 1
	pt_LOAD = 1
	pf_X = 1 // exec
	pf_R = 4 // read
)
