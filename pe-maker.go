package ass

import (
	"time"
)

type PEMaker struct{
	*baseMaker
	BinLibs map[string]string
}

func NewPEMaker(path string) (*PEMaker, error) {
	f, err := NewBaseMaker(path)
	if err != nil {
		return nil, err
	}
	return &PEMaker{
		baseMaker: f,
		BinLibs: map[string]string{},
	}, err
}

func (pe *PEMaker) WriteRelativeVirtualAddress(mark string, bit uint8) error {
	return pe.WriteRelative("BinStart", mark, PE_ADDRESS_IMAGE_BIN_BASE, bit)
}

func (pe *PEMaker) WriteMemoryAddress(mark string, bit uint8) error {
	return pe.WriteRelative("BinStart", mark, PE_ADDRESS_IMAGE_BASE + PE_ADDRESS_IMAGE_BIN_BASE, bit)
}

func (pe *PEMaker) WriteDOSHeader() { // 64字节
	pe.WriteString("MZ") // e_magic
	pe.WriteInt16(128) // e_cblp
	pe.WriteInt16(1) // e_cp
	pe.WriteInt16(0) // e_crlc
	pe.WriteInt16(4) // e_cparhdr
	pe.WriteInt16(0) // e_minalloc
	pe.WriteInt16(65535) // e_maxalloc
	pe.WriteInt16(0) // e_ss
	pe.WriteInt16(0) // e_sp
	pe.WriteInt16(0) // e_csum
	pe.WriteInt16(0) // e_ip
	pe.WriteInt16(0) // e_cs
	pe.WriteInt16(64) // e_lfarlc
	pe.WriteInt16(0) // e_ovno

	for i := 0; i < 4; i++ {
		pe.WriteInt16(0) // e_res
	}

	pe.WriteInt16(0) // e_oemid
	pe.WriteInt16(0) // e_oeminfo

	for i := 0; i < 10; i++ {
		pe.WriteInt16(0) // e_res
	}

	pe.WriteFilePointer("NTHeaders", BIT_32) // e_lfanew
}

func (pe *PEMaker) WriteNTHeader() { // 248字节
	pe.Mark("NTHeaders")
	pe.WriteString(PE_IMAGE_NT_SIGNATURE)
	pe.writeFileHeader()
	pe.writeOptionalHeader32()
}

func (pe *PEMaker) writeFileHeader() { // 20字节
	pe.WriteInt16(PE_IMAGE_FILE_MACHINE_I386) // Machine
	pe.WriteInt16(1) // NumberOfSections
	pe.WriteInt32(time.Now().Unix()) // TimeDateStamp
	pe.WriteInt32(0) // PointerToSymbolTable
	pe.WriteInt32(0) // NumberOfSymbols
	pe.WriteInt16(224) // SizeOfOptionalHeader
	pe.WriteInt16(PE_IMAGE_FILE_EXECUTABLE_IMAGE | PE_IMAGE_FILE_LINE_NUMS_STRIPPED | PE_IMAGE_FILE_LOCAL_SYMS_STRIPPED | PE_IMAGE_FILE_LARGE_ADDRESS_AWARE | PE_IMAGE_FILE_32BIT_MACHINE | PE_IMAGE_FILE_DEBUG_STRIPPED) // Characteristics
}

func (pe *PEMaker) writeOptionalHeader32() { // 224字节。Magic~标准域，ImageBase~NT附加域
	pe.WriteInt16(267) // Magic
	pe.WriteInt8(1) // MajorLinkerVersion
	pe.WriteInt8(0) // MinerLinkerVersion
	pe.WriteRelative("BinStart", "BinEnd", 0, BIT_32) // SizeOfCode
	pe.WriteInt32(0) // SizeOfInitializedData
	pe.WriteInt32(0) // SizeOfUnInitializedData
	pe.WriteInt32(PE_ADDRESS_IMAGE_BIN_BASE) // AddressOfEntryPoint
	pe.WriteInt32(PE_ADDRESS_IMAGE_BIN_BASE) // BaseOfCode
	pe.WriteInt32(PE_ADDRESS_IMAGE_BIN_BASE) // BaseOfData
	pe.WriteInt32(PE_ADDRESS_IMAGE_BASE) // ImageBase
	pe.WriteInt32(4096) // SectionAlignment
	pe.WriteInt32(512) // FileAlignment
	pe.WriteInt16(5) // MajorOperatingSystemVersion
	pe.WriteInt16(1) // MinorOperatingSystemVersion
	pe.WriteInt16(0) // MajorImageVersion
	pe.WriteInt16(0) // MinorImageVersion
	pe.WriteInt16(5) // MajorSubsystemVersion
	pe.WriteInt16(1) // MinorSubsystemVersion
	pe.WriteInt32(0) // Win32VersionValue
	pe.WriteRelative("BinStart", "BinEnd", 0, BIT_32) // SizeOfImage
	pe.WriteFilePointer("BinStart", BIT_32) // SizeOfHeaders
	pe.WriteInt32(0) // CheckSum
	pe.WriteInt16(PE_IMAGE_SUBSYSTEM_WINDOWS_CUI) // Subsystem
	pe.WriteInt16(0) // DllCharacteristics
	pe.WriteInt32(65536) // SizeOfStackReserve
	pe.WriteInt32(4096) // SizeOfStackCommit
	pe.WriteInt32(65536) // SizeOfHeapReserve
	pe.WriteInt32(4096) // SizeOfHeapCommit
	pe.WriteInt32(0) // LoaderFlags
	pe.WriteInt32(16) // NumberOfRvaAndSizes

	for i := 0; i < 16; i++ {
		// IMAGE_DATA_DIRECTORY
		if i == PE_IMAGE_DIRECTORY_ENTRY_IMPORT {
			pe.WriteRelativeVirtualAddress("ImportDescriptors", BIT_32) // VirtualAddress
			pe.WriteInt32(40) // Size
		}else{
			pe.WriteInt32(0) // VirtualAddress
			pe.WriteInt32(0) // Size
		}
	}
}