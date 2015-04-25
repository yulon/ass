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
	file *os.File
	*FileWriteManager
	imps map[string]map[string]bool
}

func CreateELF(path string) (*ELF, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	elf := &ELF{
		file: f,
		FileWriteManager: NewFileWriteManager(f),
		imps: map[string]map[string]bool{},
	}
	return elf, nil
}

func (elf *ELF) writeELFHeader() {
	// e_ident
	elf.WriteStrict(0x7f, Bit8) // ELFMAG0
	elf.Write("ELF") // ELFMAG1~3
	elf.WriteStrict(elfCLASS32, Bit8) // EI_CLASS
	elf.WriteStrict(elfDATA2LSB, Bit8) // EI_DATA
	elf.WriteStrict(ev_CURRENT, Bit8) // EI_VERSION
	elf.WriteSpace(8) // EI_PAD
	elf.WrlabPointer("IdentEnd", Bit8) // EI_NIDENT
	elf.Label("IdentEnd")

	elf.WriteStrict(et_EXEC, Bit16) // e_type
	elf.WriteStrict(em_386, Bit16) // e_machine
	elf.WriteStrict(0, Bit32) // e_version
	elf.WriteStrict(0, Bit32) // e_entry
	elf.WrlabPointer("ProgramHeaderTable", Bit32) // e_phoff
	elf.WrlabPointer("SectionHeaderTable", Bit32) // e_shoff
	elf.WriteStrict(0, Bit32) // e_flags
	elf.WrlabPointer("ELFHeaderEnd", Bit16) // e_ehsize
	elf.WriteStrict(512, Bit16) // e_phentsize
	elf.WriteStrict(1, Bit16) // e_phnum
	elf.WriteStrict(512, Bit16) // e_shentsize
	elf.WriteStrict(1, Bit16) // e_shnum
	elf.WriteStrict(shn_UNDEF, Bit16) // e_shstrndx
	elf.Label("ELFHeaderEnd")
}

/*
func (elf *ELF) writeProgramHeaderTable() {
	elf.Label("ProgramHeaderTable")
}

func (elf *ELF) writeSectionHeaderTable() {
	elf.Label("SectionHeaderTable")
}*/
