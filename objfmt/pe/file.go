package pe

import (
	"os"
	"strconv"
	"time"
	"github.com/yulon/go-octrl"
	"github.com/yulon/go-bin"
)

type File struct {
	*os.File
	w *bin.Writer
	l *octrl.Labeler
	imps map[string]map[string]func(bin.WordConv)
	datas map[uint64][]byte
	iBase int64
	fBase int64
	gui bool
	mach uint16
	wc bin.WordConv
}

func Create(path string, machine uint16, imageBase int64, gui bool) (*File, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	pe := &File{
		File: f,
		w: bin.NewWriter(f),
		l: octrl.NewLabeler(f),
		imps: map[string]map[string]func(bin.WordConv){},
		datas: map[uint64][]byte{},
		iBase: imageBase,
		gui: gui,
		mach: machine,
	}
	switch pe.mach {
		case MachineI386:
			pe.wc = bin.Dword
		case MachineAMD64:
			pe.wc = bin.Qword
	}
	pe.writeDOSHeader()
	pe.writeNTHeader()
	pe.writeSectionHeader()
	pe.sectionStart()
	return pe, nil
}

func (pe *File) Close() (err error) {
	pe.writeImportDescriptors()
	pe.writeDatas()
	pe.sectionEnd()

	err = pe.l.Close()
	if err != nil {
		pe.File.Close()
		return
	}

	err = pe.File.Close()
	return
}

func (pe *File) pitRVA(label string, wc bin.WordConv) {
	pe.l.Pit("PE.SectionStart", label, imageAlignment, wc)
}

func (pe *File) pitVA(label string, wc bin.WordConv) {
	pe.l.Pit("PE.SectionStart", label, pe.iBase + imageAlignment, wc)
}

func (pe *File) writeDOSHeader() { // 64字节
	pe.w.String("MZ") // e_magic
	pe.w.Zeros(58)
	pe.l.Pit("", "PE.NTHeaders", 0, bin.Dword) // e_lfanew
}

func (pe *File) writeNTHeader() { // 248字节
	pe.l.Label("PE.NTHeaders")
	pe.w.Dword("PE")
	pe.writeFileHeader()
	pe.writeOptionalHeader()
}

func (pe *File) writeFileHeader() { // 20字节
	pe.w.Word(pe.mach) // Machineine
	pe.w.Word(1) // NumberOfSections
	pe.w.Dword(time.Now().Unix()) // TimeDateStamp
	pe.w.Dword(0) // PointerToSymbolTable
	pe.w.Dword(0) // NumberOfSymbols
	pe.l.Pit("PE.OptionalHeaderStart", "PE.OptionalHeaderEnd", 0, bin.Word) // SizeOfOptionalHeader
	pe.w.Word(image_file_executable_image | image_file_line_nums_stripped | image_file_local_syms_stripped | image_file_large_address_aware | image_file_debug_stripped) // Characteristics
}

func (pe *File) writeOptionalHeader() {
	pe.l.Label("PE.OptionalHeaderStart")
	switch pe.mach {
		case MachineI386:
			pe.w.Word(image_nt_optional_hdr32_magic) // Magic
		case MachineAMD64:
			pe.w.Word(image_nt_optional_hdr64_magic) // Magic
	}
	pe.w.Byte(1) // MajorLinkerVersion
	pe.w.Byte(0) // MinerLinkerVersion
	pe.l.Pit("PE.SectionStart", "PE.SectionEnd", 0, bin.Dword) // SizeOfCode
	pe.w.Dword(0) // SizeOfInitializedData
	pe.w.Dword(0) // SizeOfUnInitializedData
	pe.w.Dword(imageAlignment) // AddressOfEntryPoint
	pe.w.Dword(imageAlignment) // BaseOfCode
	if pe.mach == MachineI386 {
		pe.w.Dword(imageAlignment) // BaseOfData
	}
	pe.Write(pe.wc(pe.iBase)) // ImageBase
	pe.w.Dword(imageAlignment) // SectionAlignment
	pe.w.Dword(fileAlignment) // FileAlignment
	pe.w.Word(5) // MajorOperatingSystemVersion
	pe.w.Word(1) // MinorOperatingSystemVersion
	pe.w.Word(0) // MajorImageVersion
	pe.w.Word(0) // MinorImageVersion
	pe.w.Word(5) // MajorSubsystemVersion
	pe.w.Word(1) // MinorSubsystemVersion
	pe.w.Dword(0) // Win32VersionValue
	pe.l.Pit("PE.SectionStart", "PE.SectionAlignEnd", imageAlignment, bin.Dword) // SizeOfImage
	pe.l.Pit("", "PE.SectionStart", 0, bin.Dword) // SizeOfHeaders
	pe.w.Dword(0) // CheckSum
	if pe.gui {
		pe.w.Word(image_subsystem_windows_gui) // Subsystem
	} else {
		pe.w.Word(image_subsystem_windows_cui) // Subsystem
	}
	pe.w.Word(0) // DllCharacteristics
	pe.Write(pe.wc(65536)) // SizeOfStackReserve
	pe.Write(pe.wc(4096)) // SizeOfStackCommit
	pe.Write(pe.wc(65536)) // SizeOfHeapReserve
	pe.Write(pe.wc(4096)) // SizeOfHeapCommit
	pe.w.Dword(0) // LoaderFlags
	pe.w.Dword(16) // NumberOfRvaAndSizes

	for i := 0; i < 16; i++ {
		 // IMAGE_DATA_DIRECTORY
		if i == image_directory_entry_import {
			pe.pitRVA("PE.ImportDescriptors", bin.Dword) // VirtualAddress
			pe.w.Dword(40) // Size
		} else {
			pe.w.Dword(0) // VirtualAddress
			pe.w.Dword(0) // Size
		}
	}
	pe.l.Label("PE.OptionalHeaderEnd")
}

func (pe *File) writeSectionHeader() error {
	pe.w.Qword(".codata") // Name
	pe.l.Pit("PE.SectionStart", "PE.SectionEnd", 0, bin.Dword) // VirtualSize
	pe.w.Dword(imageAlignment) // VirtualAddress
	pe.l.Pit("PE.SectionStart", "PE.SectionAlignEnd", 0, bin.Dword) // SizeOfRawData
	pe.l.Pit("", "PE.SectionStart", 0, bin.Dword) // PointerToRawData
	pe.w.Dword(0) // PointerToRelocations
	pe.w.Dword(0) // PointerToLinenumbers
	pe.w.Word(0) // NumberOfRelocations
	pe.w.Word(0) // NumberOfLinenumbers
	pe.w.Dword(image_scn_cnt_code | image_scn_mem_execute | image_scn_mem_read | image_scn_cnt_initialized_data) // Characteristics
	return nil
}

func (pe *File) sectionStart() {
	octrl.Align(pe.File, fileAlignment)
	pe.l.Label("PE.SectionStart")
}

func (pe *File) sectionEnd() {
	pe.l.Label("PE.SectionEnd")
	octrl.Align(pe.File, fileAlignment)
	pe.l.Label("PE.SectionAlignEnd")
}

func (pe *File) Seek(offset int64, whence int) (int64, error) {
	fBase, err := pe.l.Get("PE.SectionStart")
	if err != nil {
		return 0, err
	}
	if whence == 0 {
		offset = offset - (pe.iBase + imageAlignment) + fBase
	}
	newOff, err := pe.File.Seek(offset, whence)
	return newOff - fBase + pe.iBase + imageAlignment, err
}

func (pe *File) DLLFuncPtr(dll string, function string) func(bin.WordConv) {
	_, ok := pe.imps[dll]
	if !ok {
		pe.imps[dll] = map[string]func(bin.WordConv){}
		pe.imps[dll][function] = func(wc bin.WordConv) {
			pe.pitVA("DLLFunc."+dll+"."+function+".Ptr", wc)
		}
	}
	return pe.imps[dll][function]
}

func (pe *File) writeImportDescriptors() {
	pe.l.Label("PE.ImportDescriptors")
	for dll, _ := range pe.imps { // 输出 IMAGE_IMPORT_DESCRIPTOR 数组
		pe.pitRVA("DLL."+dll+".Thunk", bin.Dword) // OriginalFirstThunk
		pe.w.Dword(0) // TimeDateStamp
		pe.w.Dword(0) // ForwarderChain
		pe.pitRVA("DLL."+dll+".Name", bin.Dword) // Name
		pe.pitRVA("DLL."+dll+".Thunk", bin.Dword) // FirstThunk
	}
	pe.w.Zeros(import_descriptor_size) // 尾 IMAGE_IMPORT_DESCRIPTOR

	for dll, funcs := range pe.imps {
		pe.l.Label("DLL." + dll + ".Name")
		pe.w.Cstr(dll)

		pe.l.Label("DLL." + dll + ".Thunk")
		for function, _ := range funcs {
			pe.l.Label("DLLFunc." + dll + "." + function + ".Ptr")
			pe.pitRVA("DLLFunc."+dll+"."+function+".Name", pe.wc)
		}
		pe.Write(pe.wc(0)) // 结尾

		i := 0
		for function, _ := range funcs {
			pe.l.Label("DLLFunc." + dll + "." + function + ".Name")
			pe.w.Word(i)
			pe.w.Cstr(function)
			i++
		}
	}
}

func (pe *File) Data(d []byte) func(bin.WordConv) {
	var h uint64
	for i := 0; i < len(d); i++ {
		h = h*31 + uint64(d[i])
	}
	_, ok := pe.datas[h]
	if !ok {
		pe.datas[h] = d
	}
	return func(wc bin.WordConv) {
		pe.pitVA("Data."+strconv.FormatUint(h, 16), wc)
	}
}

func (pe *File) writeDatas() {
	for h, d := range pe.datas {
		pe.l.Label("Data." + strconv.FormatUint(h, 16))
		pe.Write(d)
	}
}
