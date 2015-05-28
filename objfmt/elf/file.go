package elf

import (
	"os"
	"github.com/yulon/go-octrl"
	"github.com/yulon/go-bin"
)

type File struct{
	*os.File
	w *bin.Writer
	l *octrl.Labeler
	imps map[string]map[string]bool
}

func Create(path string) (*File, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	elf := &File{
		File: f,
		w: bin.NewWriter(f),
		l: octrl.NewLabeler(f),
		imps: map[string]map[string]bool{},
	}
	return elf, nil
}

func (elf *File) writeELFHeader() {
	// e_ident
	elf.w.Byte(0x7f) // ELFMAG0
	elf.w.String("ELF") // ELFMAG1~3
	elf.w.Byte(CLASS32) // EI_CLASS
	elf.w.Byte(DATA2LSB) // EI_DATA
	elf.w.Byte(ev_CURRENT) // EI_VERSION
	elf.w.Zeros(8) // EI_PAD
	elf.l.Pit("", "ELF.IdentEnd", 0, bin.Byte) // EI_NIDENT
	elf.l.Label("ELF.IdentEnd")

	elf.w.Word(et_EXEC) // e_type
	elf.w.Word(em_386) // e_machine
	elf.w.Dword(0) // e_version
	elf.l.Pit("", "ELF.SegmentStart", 0, bin.Dword) // e_entry
	elf.l.Pit("", "ELF.ProgramHeaderTableStart", 0, bin.Dword) // e_phoff
	elf.w.Dword(0) // e_shoff
	elf.w.Dword(0) // e_flags
	elf.l.Pit("", "ELF.HeaderEnd", 0, bin.Word) // e_ehsize
	elf.l.Pit("ELF.ProgramHeaderTableStart", "ELF.ProgramHeaderTableEnd", 0, bin.Word) // e_phentsize
	elf.w.Word(2) // e_phnum
	elf.w.Word(0) // e_shentsize
	elf.w.Word(0) // e_shnum
	elf.w.Word(shn_UNDEF) // e_shstrndx
	elf.l.Label("ELF.HeaderEnd")
}

func (elf *File) writeProgramHeaderTable() {
	elf.l.Label("ELF.ProgramHeaderTableStart")

	elf.w.Dword(pt_LOAD) // p_type
	elf.l.Pit("", "ELF.SegmentStart", 0, bin.Dword) // p_offset
	elf.w.Dword(0x8050000) // p_vaddr
	elf.w.Dword(0) // p_paddr
	elf.l.Pit("", "ELF.SegmentStart", 0, bin.Dword) // p_filesz
	elf.w.Dword(0x10000) // p_memsz
	elf.w.Dword(pf_X + pf_R) // p_flags
	elf.w.Dword(0x10000) // p_align

	elf.w.Dword(pt_LOAD) // p_type
	elf.l.Pit("", "ELF.SegmentStart", 0, bin.Dword) // p_offset
	elf.w.Dword(0x8060000) // p_vaddr
	elf.w.Dword(0) // p_paddr
	elf.l.Pit("ELF.SegmentStart", "ELF.SegmentEnd", 0, bin.Dword) // p_filesz
	elf.l.Pit("ELF.SegmentStart", "ELF.SegmentEnd", 0, bin.Dword) // p_memsz
	elf.w.Dword(pf_X + pf_R) // p_flags
	elf.w.Dword(0x10000) // p_align

	elf.l.Label("ELF.ProgramHeaderTableEnd")
}

func (elf *File) segmentStart() {
	elf.l.Label("PE.SegmentStart")
}

func (elf *File) segmentEnd() {
	elf.l.Label("PE.SegmentEnd")
}

func (elf *File) pitVA(label string, wc bin.WordConv) {
	elf.l.Pit("PE.SegmentStart", label, 0x8060000, wc)
}
