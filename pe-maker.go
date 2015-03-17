package ass

import (
	"time"
)

type PEMaker struct{
	*baseMaker
	imps map[string][]string
	imgBase int64
	cui bool
}

func NewPEMaker(path string, cpu int, imageBase int64, console bool) (*PEMaker, error) {
	f, err := NewBaseMaker(path)
	if err != nil {
		return nil, err
	}
	pe := &PEMaker{
		baseMaker: f,
		imps: map[string][]string{},
		imgBase: imageBase,
		cui: console,
	}
	pe.writeDOSHeader()
	pe.writeNTHeader()
	pe.writeSectionHeader()
	pe.sectionStart()
	return pe, err
}

func (pe *PEMaker) Close() error {
	pe.writeImportDescriptors()
	pe.sectionEnd()
	return pe.baseMaker.Close()
}

func (pe *PEMaker) WriteRVA(mark string, bit int) {
	pe.WriteDifference("SectionStart", mark, pe_RVA_SECTION, bit)
}

func (pe *PEMaker) WriteVA(mark string, bit int) {
	pe.WriteDifference("SectionStart", mark, pe.imgBase + pe_RVA_SECTION, bit)
}

func (pe *PEMaker) writeDOSHeader() { // 64字节
	pe.Write("MZ") // e_magic
	pe.WriteStrict(128, Bit16) // e_cblp
	pe.WriteStrict(1, Bit16) // e_cp
	pe.WriteStrict(0, Bit16) // e_crlc
	pe.WriteStrict(4, Bit16) // e_cparhdr
	pe.WriteStrict(0, Bit16) // e_minalloc
	pe.WriteStrict(65535, Bit16) // e_maxalloc
	pe.WriteStrict(0, Bit16) // e_ss
	pe.WriteStrict(0, Bit16) // e_sp
	pe.WriteStrict(0, Bit16) // e_csum
	pe.WriteStrict(0, Bit16) // e_ip
	pe.WriteStrict(0, Bit16) // e_cs
	pe.WriteStrict(64, Bit16) // e_lfarlc
	pe.WriteStrict(0, Bit16) // e_ovno

	for i := 0; i < 4; i++ {
		pe.WriteStrict(0, Bit16) // e_res
	}

	pe.WriteStrict(0, Bit16) // e_oemid
	pe.WriteStrict(0, Bit16) // e_oeminfo

	for i := 0; i < 10; i++ {
		pe.WriteStrict(0, Bit16) // e_res
	}

	pe.WritePointer("NTHeaders", Bit32) // e_lfanew
}

func (pe *PEMaker) writeNTHeader() { // 248字节
	pe.Label("NTHeaders")
	pe.WriteStrict(pe_IMAGE_NT_SIGNATURE, Bit32)
	pe.writeFileHeader()
	pe.writeOptionalHeader32()
}

func (pe *PEMaker) writeFileHeader() { // 20字节
	pe.WriteStrict(pe_IMAGE_FILE_MACHINE_I386, Bit16) // Machine
	pe.WriteStrict(1, Bit16) // NumberOfSections
	pe.WriteStrict(time.Now().Unix(), Bit32) // TimeDateStamp
	pe.WriteStrict(0, Bit32) // PointerToSymbolTable
	pe.WriteStrict(0, Bit32) // NumberOfSymbols
	pe.WriteStrict(224, Bit16) // SizeOfOptionalHeader
	pe.WriteStrict(pe_IMAGE_FILE_EXECUTABLE_IMAGE | pe_IMAGE_FILE_LINE_NUMS_STRIPPED | pe_IMAGE_FILE_LOCAL_SYMS_STRIPPED | pe_IMAGE_FILE_LARGE_ADDRESS_AWARE | pe_IMAGE_FILE_32BIT_MACHINE | pe_IMAGE_FILE_DEBUG_STRIPPED, Bit16) // Characteristics
}

func (pe *PEMaker) writeOptionalHeader32() { // 224字节。Magic~标准域，ImageBase~NT附加域
	pe.WriteStrict(267, Bit16) // Magic
	pe.WriteStrict(1, Bit8) // MajorLinkerVersion
	pe.WriteStrict(0, Bit8) // MinerLinkerVersion
	pe.WriteDifference("SectionStart", "SectionEnd", 0, Bit32) // SizeOfCode
	pe.WriteStrict(0, Bit32) // SizeOfInitializedData
	pe.WriteStrict(0, Bit32) // SizeOfUnInitializedData
	pe.WriteStrict(pe_RVA_SECTION, Bit32) // AddressOfEntryPoint
	pe.WriteStrict(pe_RVA_SECTION, Bit32) // BaseOfCode
	pe.WriteStrict(pe_RVA_SECTION, Bit32) // BaseOfData
	pe.WriteStrict(pe.imgBase, Bit32) // ImageBase
	pe.WriteStrict(pe_ALIGNMENT_IMAGE, Bit32) // SectionAlignment
	pe.WriteStrict(pe_ALIGNMENT_FILE, Bit32) // FileAlignment
	pe.WriteStrict(5, Bit16) // MajorOperatingSystemVersion
	pe.WriteStrict(1, Bit16) // MinorOperatingSystemVersion
	pe.WriteStrict(0, Bit16) // MajorImageVersion
	pe.WriteStrict(0, Bit16) // MinorImageVersion
	pe.WriteStrict(5, Bit16) // MajorSubsystemVersion
	pe.WriteStrict(1, Bit16) // MinorSubsystemVersion
	pe.WriteStrict(0, Bit32) // Win32VersionValue
	pe.WriteDifference("SectionStart", "SectionAlignEnd", pe_RVA_SECTION, Bit32) // SizeOfImage
	pe.WritePointer("SectionStart", Bit32) // SizeOfHeaders
	pe.WriteStrict(0, Bit32) // CheckSum
	if pe.cui {
		pe.WriteStrict(pe_IMAGE_SUBSYSTEM_WINDOWS_CUI, Bit16) // Subsystem
	}else{
		pe.WriteStrict(pe_IMAGE_SUBSYSTEM_WINDOWS_GUI, Bit16) // Subsystem
	}
	pe.WriteStrict(0, Bit16) // DllCharacteristics
	pe.WriteStrict(65536, Bit32) // SizeOfStackReserve
	pe.WriteStrict(4096, Bit32) // SizeOfStackCommit
	pe.WriteStrict(65536, Bit32) // SizeOfHeapReserve
	pe.WriteStrict(4096, Bit32) // SizeOfHeapCommit
	pe.WriteStrict(0, Bit32) // LoaderFlags
	pe.WriteStrict(16, Bit32) // NumberOfRvaAndSizes

	for i := 0; i < 16; i++ {
		// IMAGE_DATA_DIRECTORY
		if i == pe_IMAGE_DIRECTORY_ENTRY_IMPORT {
			pe.WriteRVA("ImportDescriptors", Bit32) // VirtualAddress
			pe.WriteStrict(40, Bit32) // Size
		}else{
			pe.WriteStrict(0, Bit32) // VirtualAddress
			pe.WriteStrict(0, Bit32) // Size
		}
	}
}

func (pe *PEMaker) writeSectionHeader() error {
	pe.WriteStrict(".codata", Bit64) // Name
	pe.WriteDifference("SectionStart", "SectionEnd", 0, Bit32) // VirtualSize
	pe.WriteStrict(pe_RVA_SECTION, Bit32) // VirtualAddress
	pe.WriteDifference("SectionStart", "SectionAlignEnd", 0, Bit32) // SizeOfRawData
	pe.WritePointer("SectionStart", Bit32) // PointerToRawData
	pe.WriteStrict(0, Bit32) // PointerToRelocations
	pe.WriteStrict(0, Bit32) // PointerToLinenumbers
	pe.WriteStrict(0, Bit16) // NumberOfRelocations
	pe.WriteStrict(0, Bit16) // NumberOfLinenumbers
	pe.WriteStrict(pe_IMAGE_SCN_CNT_CODE | pe_IMAGE_SCN_MEM_EXECUTE | pe_IMAGE_SCN_MEM_READ | pe_IMAGE_SCN_CNT_INITIALIZED_DATA, Bit32) // Characteristics
	return nil
}

func (pe *PEMaker) sectionStart() {
	m := pe.Len() % pe_ALIGNMENT_FILE
	if m > 0 {
		pe.WriteSpace(int(pe_ALIGNMENT_FILE - m))
	}
	pe.Label("SectionStart")
}

func (pe *PEMaker) sectionEnd() {
	pe.Label("SectionEnd")
	m := pe.Len() % pe_ALIGNMENT_FILE
	if m > 0 {
		pe.WriteSpace(int(pe_ALIGNMENT_FILE - m))
	}
	pe.Label("SectionAlignEnd")
}

func (pe *PEMaker) Import(dll string, function string) {
	pe.imps[dll] = append(pe.imps[dll], function)
}

const(
	peImportDescriptorSize = 20
)

func (pe *PEMaker) writeImportDescriptors() {
	pe.Label("ImportDescriptors")
	for dll, _ := range pe.imps { // 输出 IMAGE_IMPORT_DESCRIPTOR 数组
		pe.WriteRVA("Imp.Lib." + dll + ".Thunk", Bit32) // OriginalFirstThunk
		pe.WriteStrict(0, Bit32) // TimeDateStamp
		pe.WriteStrict(0, Bit32) // ForwarderChain
		pe.WriteRVA("Imp.Lib." + dll + ".Name", Bit32) // Name
		pe.WriteRVA("Imp.Lib." + dll + ".Thunk", Bit32) // FirstThunk
	}
	pe.WriteSpace(peImportDescriptorSize) // 尾 IMAGE_IMPORT_DESCRIPTOR

	for dll, funcs := range pe.imps {
		pe.Label("Imp.Lib." + dll + ".Name")
		pe.WriteStrict(dll, len(dll) + 1)

		pe.Label("Imp.Lib." + dll + ".Thunk")
		for i := 0; i < len(funcs); i++ {
			pe.Label("Imp.Func." + funcs[i])
			pe.WriteRVA("Imp.Func." + funcs[i] + ".Name", Bit32)
		}
		pe.WriteSpace(Bit32) // 结尾

		for i := 0; i < len(funcs); i++ {
			pe.Label("Imp.Func." + funcs[i] + ".Name")
			pe.WriteStrict(i, Bit16)
			pe.WriteStrict(funcs[i], len(funcs[i]) + 1)
		}
	}
}