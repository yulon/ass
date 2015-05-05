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
	pt_LOAD = 1
	pf_X = 1 // exec
	pf_R = 4 // read
)

type ELF struct{
	f *os.File
	l *labeler
	imps map[string]map[string]bool
}

func CreateELF(path string) (*ELF, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	elf := &ELF{
		f: f,
		l: newLabeler(f),
		imps: map[string]map[string]bool{},
	}
	return elf, nil
}

func (elf *ELF) writeELFHeader() {
	// e_ident
	elf.f.Write(Num8(0x7f)) // ELFMAG0
	elf.f.Write([]byte("ELF")) // ELFMAG1~3
	elf.f.Write(Num8(elfCLASS32)) // EI_CLASS
	elf.f.Write(Num8(elfDATA2LSB)) // EI_DATA
	elf.f.Write(Num8(ev_CURRENT)) // EI_VERSION
	elf.f.Write(Zeros(8)) // EI_PAD
	elf.l.PitPointer("ELF.IdentEnd", Num8) // EI_NIDENT
	elf.l.Label("ELF.IdentEnd")

	elf.f.Write(Num16L(et_EXEC)) // e_type
	elf.f.Write(Num16L(em_386)) // e_machine
	elf.f.Write(Num32L(0)) // e_version
	elf.l.PitPointer("ELF.SegmentStart", Num32L) // e_entry
	elf.l.PitPointer("ELF.ProgramHeaderTableStart", Num32L) // e_phoff
	elf.f.Write(Num32L(0)) // e_shoff
	elf.f.Write(Num32L(0)) // e_flags
	elf.l.PitPointer("ELF.HeaderEnd", Num16L) // e_ehsize
	elf.l.PitOffset("ELF.ProgramHeaderTableStart", "ELF.ProgramHeaderTableEnd", 0, Num16L) // e_phentsize
	elf.f.Write(Num16L(1)) // e_phnum
	elf.f.Write(Num16L(0)) // e_shentsize
	elf.f.Write(Num16L(0)) // e_shnum
	elf.f.Write(Num16L(shn_UNDEF)) // e_shstrndx
	elf.l.Label("ELF.HeaderEnd")
}

func (elf *ELF) writeProgramHeaderTable() {
	elf.l.Label("ELF.ProgramHeaderTableStart")
	elf.f.Write(Num32L(pt_LOAD)) // p_type
	elf.l.PitPointer("ELF.SegmentStart", Num32L) // p_offset
	elf.f.Write(Num32L(0x8000)) // p_vaddr
	elf.f.Write(Num32L(0x8000)) // p_paddr
	elf.l.PitOffset("ELF.SegmentStart", "ELF.SegmentEnd", 0, Num32L) // p_filesz
	elf.l.PitOffset("ELF.SegmentStart", "ELF.SegmentEnd", 0, Num32L) // p_memsz
	elf.f.Write(Num32L(pf_X + pf_R)) // p_flags
	elf.f.Write(Num32L(0)) // p_align
	elf.l.Label("ELF.ProgramHeaderTableEnd")
}

func (pe *PE) segmentStart() {
	pe.l.Label("PE.SegmentStart")
}

func (pe *PE) segmentEnd() {
	pe.l.Label("PE.SegmentEnd")
}
