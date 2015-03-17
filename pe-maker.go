package ass

import (
	"time"
)

type PEMaker struct{
	*baseMaker
	imps map[string][]string
}

func NewPEMaker(path string) (*PEMaker, error) {
	f, err := NewBaseMaker(path)
	if err != nil {
		return nil, err
	}
	return &PEMaker{
		baseMaker: f,
		imps: map[string][]string{},
	}, err
}

func (pe *PEMaker) WriteRVA(mark string, bit int) {
	pe.WriteDifference("SectionStart", mark, PE_RVA_SECTION, bit)
}

func (pe *PEMaker) WriteVA(mark string, bit int) {
	pe.WriteDifference("SectionStart", mark, PE_VA_BASE + PE_RVA_SECTION, bit)
}

func (pe *PEMaker) WriteDOSHeader() { // 64字节
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

func (pe *PEMaker) WriteNTHeader() { // 248字节
	pe.Label("NTHeaders")
	pe.WriteStrict(PE_IMAGE_NT_SIGNATURE, Bit32)
	pe.writeFileHeader()
	pe.writeOptionalHeader32()
}

func (pe *PEMaker) writeFileHeader() { // 20字节
	pe.WriteStrict(PE_IMAGE_FILE_MACHINE_I386, Bit16) // Machine
	pe.WriteStrict(1, Bit16) // NumberOfSections
	pe.WriteStrict(time.Now().Unix(), Bit32) // TimeDateStamp
	pe.WriteStrict(0, Bit32) // PointerToSymbolTable
	pe.WriteStrict(0, Bit32) // NumberOfSymbols
	pe.WriteStrict(224, Bit16) // SizeOfOptionalHeader
	pe.WriteStrict(PE_IMAGE_FILE_EXECUTABLE_IMAGE | PE_IMAGE_FILE_LINE_NUMS_STRIPPED | PE_IMAGE_FILE_LOCAL_SYMS_STRIPPED | PE_IMAGE_FILE_LARGE_ADDRESS_AWARE | PE_IMAGE_FILE_32BIT_MACHINE | PE_IMAGE_FILE_DEBUG_STRIPPED, Bit16) // Characteristics
}

func (pe *PEMaker) writeOptionalHeader32() { // 224字节。Magic~标准域，ImageBase~NT附加域
	pe.WriteStrict(267, Bit16) // Magic
	pe.WriteStrict(1, Bit8) // MajorLinkerVersion
	pe.WriteStrict(0, Bit8) // MinerLinkerVersion
	pe.WriteDifference("SectionStart", "SectionEnd", 0, Bit32) // SizeOfCode
	pe.WriteStrict(0, Bit32) // SizeOfInitializedData
	pe.WriteStrict(0, Bit32) // SizeOfUnInitializedData
	pe.WriteStrict(PE_RVA_SECTION, Bit32) // AddressOfEntryPoint
	pe.WriteStrict(PE_RVA_SECTION, Bit32) // BaseOfCode
	pe.WriteStrict(PE_RVA_SECTION, Bit32) // BaseOfData
	pe.WriteStrict(PE_VA_BASE, Bit32) // ImageBase
	pe.WriteStrict(PE_ALIGNMENT_IMAGE, Bit32) // SectionAlignment
	pe.WriteStrict(PE_ALIGNMENT_FILE, Bit32) // FileAlignment
	pe.WriteStrict(5, Bit16) // MajorOperatingSystemVersion
	pe.WriteStrict(1, Bit16) // MinorOperatingSystemVersion
	pe.WriteStrict(0, Bit16) // MajorImageVersion
	pe.WriteStrict(0, Bit16) // MinorImageVersion
	pe.WriteStrict(5, Bit16) // MajorSubsystemVersion
	pe.WriteStrict(1, Bit16) // MinorSubsystemVersion
	pe.WriteStrict(0, Bit32) // Win32VersionValue
	pe.WriteDifference("SectionStart", "SectionAlignEnd", PE_RVA_SECTION, Bit32) // SizeOfImage
	pe.WritePointer("SectionStart", Bit32) // SizeOfHeaders
	pe.WriteStrict(0, Bit32) // CheckSum
	pe.WriteStrict(PE_IMAGE_SUBSYSTEM_WINDOWS_CUI, Bit16) // Subsystem
	pe.WriteStrict(0, Bit16) // DllCharacteristics
	pe.WriteStrict(65536, Bit32) // SizeOfStackReserve
	pe.WriteStrict(4096, Bit32) // SizeOfStackCommit
	pe.WriteStrict(65536, Bit32) // SizeOfHeapReserve
	pe.WriteStrict(4096, Bit32) // SizeOfHeapCommit
	pe.WriteStrict(0, Bit32) // LoaderFlags
	pe.WriteStrict(16, Bit32) // NumberOfRvaAndSizes

	for i := 0; i < 16; i++ {
		// IMAGE_DATA_DIRECTORY
		if i == PE_IMAGE_DIRECTORY_ENTRY_IMPORT {
			pe.WriteRVA("ImportDescriptors", Bit32) // VirtualAddress
			pe.WriteStrict(40, Bit32) // Size
		}else{
			pe.WriteStrict(0, Bit32) // VirtualAddress
			pe.WriteStrict(0, Bit32) // Size
		}
	}
}

func (pe *PEMaker) WriteSectionHeader() error {
	pe.WriteStrict(".codata", Bit64) // Name
	pe.WriteDifference("SectionStart", "SectionEnd", 0, Bit32) // VirtualSize
	pe.WriteStrict(PE_RVA_SECTION, Bit32) // VirtualAddress
	pe.WriteDifference("SectionStart", "SectionAlignEnd", 0, Bit32) // SizeOfRawData
	pe.WritePointer("SectionStart", Bit32) // PointerToRawData
	pe.WriteStrict(0, Bit32) // PointerToRelocations
	pe.WriteStrict(0, Bit32) // PointerToLinenumbers
	pe.WriteStrict(0, Bit16) // NumberOfRelocations
	pe.WriteStrict(0, Bit16) // NumberOfLinenumbers
	pe.WriteStrict(PE_IMAGE_SCN_CNT_CODE | PE_IMAGE_SCN_MEM_EXECUTE | PE_IMAGE_SCN_MEM_READ | PE_IMAGE_SCN_CNT_INITIALIZED_DATA, Bit32) // Characteristics
	return nil
}

func (pe *PEMaker) SectionStart() {
	m := pe.Len() % PE_ALIGNMENT_FILE
	if m > 0 {
		pe.WriteSpace(int(PE_ALIGNMENT_FILE - m))
	}
	pe.Label("SectionStart")

}

func (pe *PEMaker) SectionEnd() {
	pe.Label("SectionEnd")
	m := pe.Len() % PE_ALIGNMENT_FILE
	if m > 0 {
		pe.WriteSpace(int(PE_ALIGNMENT_FILE - m))
	}
	pe.Label("SectionAlignEnd")
}

func (pe *PEMaker) Import(dll string, function string) {
	pe.imps[dll] = append(pe.imps[dll], function)
}

func (pe *PEMaker) WriteImportDescriptors() {
	pe.Label("ImportDescriptors")
	for dll, _ := range pe.imps { // 输出 IMAGE_IMPORT_DESCRIPTOR 数组
		pe.WriteRVA("Imp.Lib." + dll + ".Thunk", Bit32) // OriginalFirstThunk
		pe.WriteStrict(0, Bit32) // TimeDateStamp
		pe.WriteStrict(0, Bit32) // ForwarderChain
		pe.WriteRVA("Imp.Lib." + dll + ".Name", Bit32) // Name
		pe.WriteRVA("Imp.Lib." + dll + ".Thunk", Bit32) // FirstThunk
	}
	pe.WriteSpace(20) // 尾 IMAGE_IMPORT_DESCRIPTOR

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