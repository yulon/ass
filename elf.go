package ass

import (
	"os"
)

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
	elfCLASS32 = 1 // 32-bit objects
	elfCLASS64 = 2 // 64-bit objects
	ev_CURRENT = 1
	elfDATA2LSB = 1
)

type ELF struct{
	*fileWriteManager
	imps map[string]map[string]bool
}

func CreateELF(path string) (*ELF, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	elf := &ELF{
		fileWriteManager: newFileWriteManager(f),
		imps: map[string]map[string]bool{},
	}
	return elf, nil
}

func (elf *ELF) writeELFHeader() {
	// e_ident
	elf.Write(BinNum8(0x7f)) // ELFMAG0
	elf.Write([]byte("ELF")) // ELFMAG1~3
	elf.Write(BinNum8(elfCLASS32)) // EI_CLASS
	elf.Write(BinNum8(elfDATA2LSB)) // EI_DATA
	elf.Write(BinNum8(ev_CURRENT)) // EI_VERSION
	elf.WriteSpace(8) // EI_PAD
	elf.WrlabPointer("ELF.IdentEnd", BinNum8) // EI_NIDENT
	elf.Label("ELF.IdentEnd")

	elf.Write(BinNum16L(et_EXEC)) // e_type
	elf.Write(BinNum16L(em_386)) // e_machine
	elf.Write(BinNum32L(0)) // e_version
	elf.Write(BinNum32L(0)) // e_entry
	elf.WrlabPointer("ELF.ProgramHeaderTable", BinNum32L) // e_phoff
	elf.WrlabPointer("ELF.SectionHeaderTable", BinNum32L) // e_shoff
	elf.Write(BinNum32L(0)) // e_flags
	elf.WrlabPointer("ELF.HeaderEnd", BinNum16L) // e_ehsize
	elf.Write(BinNum16L(512)) // e_phentsize
	elf.Write(BinNum16L(1)) // e_phnum
	elf.Write(BinNum16L(512)) // e_shentsize
	elf.Write(BinNum16L(1)) // e_shnum
	elf.Write(BinNum16L(shn_UNDEF)) // e_shstrndx
	elf.Label("ELF.HeaderEnd")
}

/*
func (elf *ELF) writeProgramHeaderTable() {
	elf.Label("ELF.ProgramHeaderTable")
}

func (elf *ELF) writeSectionHeaderTable() {
	elf.Label("ELF.SectionHeaderTable")
}*/
