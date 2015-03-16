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

func (pe *PEMaker) WriteVirtualAddress(mark string, bit uint8) error {
	return pe.WriteRelative("BinStart", mark, PE_ADDRESS_IMAGE_BIN_BASE, bit)
}

func (pe *PEMaker) WriteMemoryAddress(mark string, bit uint8) error {
	return pe.WriteRelative("BinStart", mark, PE_ADDRESS_IMAGE_BASE + PE_ADDRESS_IMAGE_BIN_BASE, bit)
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
	pe.Write(PE_IMAGE_NT_SIGNATURE)
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
	pe.WriteRelative("BinStart", "BinEnd", 0, BIT_32) // SizeOfCode
	pe.Write(uint32(0)) // SizeOfInitializedData
	pe.Write(uint32(0)) // SizeOfUnInitializedData
	pe.Write(uint32(PE_ADDRESS_IMAGE_BIN_BASE)) // AddressOfEntryPoint
	pe.Write(uint32(PE_ADDRESS_IMAGE_BIN_BASE)) // BaseOfCode
	pe.Write(uint32(PE_ADDRESS_IMAGE_BIN_BASE)) // BaseOfData
	pe.Write(uint32(PE_ADDRESS_IMAGE_BASE)) // ImageBase
	pe.Write(uint32(4096)) // SectionAlignment
	pe.Write(uint32(512)) // FileAlignment
	pe.Write(uint16(5)) // MajorOperatingSystemVersion
	pe.Write(uint16(1)) // MinorOperatingSystemVersion
	pe.Write(uint16(0)) // MajorImageVersion
	pe.Write(uint16(0)) // MinorImageVersion
	pe.Write(uint16(5)) // MajorSubsystemVersion
	pe.Write(uint16(1)) // MinorSubsystemVersion
	pe.Write(uint32(0)) // Win32VersionValue
	pe.WriteRelative("BinStart", "BinEnd", 0, BIT_32) // SizeOfImage
	pe.WriteFilePointer("BinStart", BIT_32) // SizeOfHeaders
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