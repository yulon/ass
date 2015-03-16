package ass

import (
	"time"
	"errors"
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

func (pe *PEMaker) WriteVirtualAddress(mark string, bit uint8) error {
	return pe.WriteRelative("SectionStart", mark, PE_VA_SECTION, bit)
}

func (pe *PEMaker) WriteMemoryAddress(mark string, bit uint8) error {
	return pe.WriteRelative("SectionStart", mark, PE_MA_BASE + PE_VA_SECTION, bit)
}

func (pe *PEMaker) WriteDOSHeader() { // 64字节
	pe.Write("MZ") // e_magic
	pe.Write(uint16(128)) // e_cblp
	pe.Write(uint16(1)) // e_cp
	pe.Write(uint16(0)) // e_crlc
	pe.Write(uint16(4)) // e_cparhdr
	pe.Write(uint16(0)) // e_minalloc
	pe.Write(uint16(65535)) // e_maxalloc
	pe.Write(uint16(0)) // e_ss
	pe.Write(uint16(0)) // e_sp
	pe.Write(uint16(0)) // e_csum
	pe.Write(uint16(0)) // e_ip
	pe.Write(uint16(0)) // e_cs
	pe.Write(uint16(64)) // e_lfarlc
	pe.Write(uint16(0)) // e_ovno

	for i := 0; i < 4; i++ {
		pe.Write(uint16(0)) // e_res
	}

	pe.Write(uint16(0)) // e_oemid
	pe.Write(uint16(0)) // e_oeminfo

	for i := 0; i < 10; i++ {
		pe.Write(uint16(0)) // e_res
	}

	pe.WriteFilePointer("NTHeaders", BIT_32) // e_lfanew
}

func (pe *PEMaker) WriteNTHeader() { // 248字节
	pe.Label("NTHeaders")
	pe.Write(append([]byte(PE_IMAGE_NT_SIGNATURE), 0, 0))
	pe.writeFileHeader()
	pe.writeOptionalHeader32()
}

func (pe *PEMaker) writeFileHeader() { // 20字节
	pe.Write(uint16(PE_IMAGE_FILE_MACHINE_I386)) // Machine
	pe.Write(uint16(1)) // NumberOfSections
	pe.Write(uint32(time.Now().Unix())) // TimeDateStamp
	pe.Write(uint32(0)) // PointerToSymbolTable
	pe.Write(uint32(0)) // NumberOfSymbols
	pe.Write(uint16(224)) // SizeOfOptionalHeader
	pe.Write(uint16(PE_IMAGE_FILE_EXECUTABLE_IMAGE | PE_IMAGE_FILE_LINE_NUMS_STRIPPED | PE_IMAGE_FILE_LOCAL_SYMS_STRIPPED | PE_IMAGE_FILE_LARGE_ADDRESS_AWARE | PE_IMAGE_FILE_32BIT_MACHINE | PE_IMAGE_FILE_DEBUG_STRIPPED)) // Characteristics
}

func (pe *PEMaker) writeOptionalHeader32() { // 224字节。Magic~标准域，ImageBase~NT附加域
	pe.Write(uint16(267)) // Magic
	pe.Write(uint8(1)) // MajorLinkerVersion
	pe.Write(uint8(0)) // MinerLinkerVersion
	pe.WriteRelative("SectionStart", "SectionEnd", 0, BIT_32) // SizeOfCode
	pe.Write(uint32(0)) // SizeOfInitializedData
	pe.Write(uint32(0)) // SizeOfUnInitializedData
	pe.Write(uint32(PE_VA_SECTION)) // AddressOfEntryPoint
	pe.Write(uint32(PE_VA_SECTION)) // BaseOfCode
	pe.Write(uint32(PE_VA_SECTION)) // BaseOfData
	pe.Write(uint32(PE_MA_BASE)) // ImageBase
	pe.Write(uint32(PE_ALIGNMENT_IMAGE)) // SectionAlignment
	pe.Write(uint32(PE_ALIGNMENT_FILE)) // FileAlignment
	pe.Write(uint16(5)) // MajorOperatingSystemVersion
	pe.Write(uint16(1)) // MinorOperatingSystemVersion
	pe.Write(uint16(0)) // MajorImageVersion
	pe.Write(uint16(0)) // MinorImageVersion
	pe.Write(uint16(5)) // MajorSubsystemVersion
	pe.Write(uint16(1)) // MinorSubsystemVersion
	pe.Write(uint32(0)) // Win32VersionValue
	pe.WriteRelative("SectionStart", "SectionAlignEnd", PE_VA_SECTION, BIT_32) // SizeOfImage
	pe.WriteFilePointer("SectionStart", BIT_32) // SizeOfHeaders
	pe.Write(uint32(0)) // CheckSum
	pe.Write(uint16(PE_IMAGE_SUBSYSTEM_WINDOWS_CUI)) // Subsystem
	pe.Write(uint16(0)) // DllCharacteristics
	pe.Write(uint32(65536)) // SizeOfStackReserve
	pe.Write(uint32(4096)) // SizeOfStackCommit
	pe.Write(uint32(65536)) // SizeOfHeapReserve
	pe.Write(uint32(4096)) // SizeOfHeapCommit
	pe.Write(uint32(0)) // LoaderFlags
	pe.Write(uint32(16)) // NumberOfRvaAndSizes

	for i := 0; i < 16; i++ {
		// IMAGE_DATA_DIRECTORY
		if i == PE_IMAGE_DIRECTORY_ENTRY_IMPORT {
			pe.WriteVirtualAddress("ImportDescriptors", BIT_32) // VirtualAddress
			pe.Write(uint32(40)) // Size
		}else{
			pe.Write(uint32(0)) // VirtualAddress
			pe.Write(uint32(0)) // Size
		}
	}
}

var SectionNameExceeded = errors.New("Section Name Exceeded 8 Characters")

func (pe *PEMaker) WriteSectionHeader(name string) error {
	l, _ := pe.Write(name) // Name
	if l < 8 {
		pe.WriteSpace(8 - l)
	}else if l > 8 {
		return SectionNameExceeded
	}
	pe.WriteRelative("SectionStart", "SectionEnd", 0, BIT_32) // VirtualSize
	pe.Write(int32(PE_VA_SECTION)) // VirtualAddress
	pe.WriteRelative("SectionStart", "SectionAlignEnd", 0, BIT_32) // SizeOfRawData
	pe.WriteFilePointer("SectionStart", BIT_32) // PointerToRawData
	pe.Write(uint32(0)) // PointerToRelocations
	pe.Write(uint32(0)) // PointerToLinenumbers
	pe.Write(uint16(0)) // NumberOfRelocations
	pe.Write(uint16(0)) // NumberOfLinenumbers
	pe.Write(uint32(PE_IMAGE_SCN_CNT_CODE | PE_IMAGE_SCN_MEM_EXECUTE | PE_IMAGE_SCN_MEM_READ | PE_IMAGE_SCN_CNT_INITIALIZED_DATA)) // Characteristics
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
		pe.WriteVirtualAddress("Imp.Lib." + dll + ".Thunk", BIT_32) // OriginalFirstThunk
		pe.Write(uint32(0)) // TimeDateStamp
		pe.Write(uint32(0)) // ForwarderChain
		pe.WriteVirtualAddress("Imp.Lib." + dll + ".Name", BIT_32) // Name
		pe.WriteVirtualAddress("Imp.Lib." + dll + ".Thunk", BIT_32) // FirstThunk
	}
	pe.WriteSpace(20) // 尾 IMAGE_IMPORT_DESCRIPTOR

	for dll, funcs := range pe.imps {
		pe.Label("Imp.Lib." + dll + ".Name")
		pe.Write(append([]byte(dll), 0))

		pe.Label("Imp.Lib." + dll + ".Thunk")
		for i := 0; i < len(funcs); i++ {
			pe.Label("Imp.Func." + funcs[i])
			pe.WriteVirtualAddress("Imp.Func." + funcs[i] + ".Name", BIT_32)
		}
		pe.Write(uint32(0)) // 结尾

		for i := 0; i < len(funcs); i++ {
			pe.Label("Imp.Func." + funcs[i] + ".Name")
			pe.Write(uint16(i))
			pe.Write(append([]byte(funcs[i]), 0))
		}
	}
}