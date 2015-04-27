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
	elf.Write(Num8(0x7f)) // ELFMAG0
	elf.Write([]byte("ELF")) // ELFMAG1~3
	elf.Write(Num8(elfCLASS32)) // EI_CLASS
	elf.Write(Num8(elfDATA2LSB)) // EI_DATA
	elf.Write(Num8(ev_CURRENT)) // EI_VERSION
	elf.Write(Zeros(8)) // EI_PAD
	elf.PitPointer("ELF.IdentEnd", Num8) // EI_NIDENT
	elf.Label("ELF.IdentEnd")

	elf.Write(Num16L(et_EXEC)) // e_type
	elf.Write(Num16L(em_386)) // e_machine
	elf.Write(Num32L(0)) // e_version
	elf.Write(Num32L(0)) // e_entry
	elf.PitPointer("ELF.ProgramHeaderTable", Num32L) // e_phoff
	elf.PitPointer("ELF.SectionHeaderTable", Num32L) // e_shoff
	elf.Write(Num32L(0)) // e_flags
	elf.PitPointer("ELF.HeaderEnd", Num16L) // e_ehsize
	elf.Write(Num16L(512)) // e_phentsize
	elf.Write(Num16L(1)) // e_phnum
	elf.Write(Num16L(512)) // e_shentsize
	elf.Write(Num16L(1)) // e_shnum
	elf.Write(Num16L(shn_UNDEF)) // e_shstrndx
	elf.Label("ELF.HeaderEnd")
}

/*
func (elf *ELF) writeProgramHeaderTable() {
	elf.Label("ELF.ProgramHeaderTable")
}

func (elf *ELF) writeSectionHeaderTable() {
	elf.Label("ELF.SectionHeaderTable")
}*/
