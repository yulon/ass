package ass

import (
	"time"
	"os"
)

type PE struct{
	file *os.File
	*FileWriteManager
	imps map[string][]string
	imgBase int64
	cui bool
	cpu int
}

func CreatePE(path string, machine int, imageBase int64, console bool) (*PE, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	pe := &PE{
		file: f,
		FileWriteManager: NewFileWriteManager(f),
		imps: map[string][]string{},
		imgBase: imageBase,
		cui: console,
		cpu: machine,
	}
	pe.writeDOSHeader()
	pe.writeNTHeader()
	pe.writeSectionHeader()
	pe.sectionStart()
	return pe, nil
}

func (pe *PE) Close() error {
	pe.writeImportDescriptors()
	pe.sectionEnd()
	err := pe.FileWriteManager.Fill()
	if err != nil {
		pe.file.Close()
		return err
	}else{
		return pe.file.Close()
	}
}

func (pe *PE) WriteRVA(mark string) {
	pe.WriteDifference("SectionStart", mark, pe_RVA_SECTION, Bit32)
}

func (pe *PE) WriteVA(mark string) {
	pe.WriteDifference("SectionStart", mark, pe.imgBase + pe_RVA_SECTION, Bit32)
}

func (pe *PE) writeDOSHeader() { // 64字节
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

func (pe *PE) writeNTHeader() { // 248字节
	pe.Label("NTHeaders")
	pe.WriteStrict(pe_IMAGE_NT_SIGNATURE, Bit32)
	pe.writeFileHeader()
	pe.writeOptionalHeader32()
}

func (pe *PE) writeFileHeader() { // 20字节
	pe.WriteStrict(pe_IMAGE_FILE_MACHINE_I386, Bit16) // Machine
	pe.WriteStrict(1, Bit16) // NumberOfSections
	pe.WriteStrict(time.Now().Unix(), Bit32) // TimeDateStamp
	pe.WriteStrict(0, Bit32) // PointerToSymbolTable
	pe.WriteStrict(0, Bit32) // NumberOfSymbols
	pe.WriteStrict(224, Bit16) // SizeOfOptionalHeader
	pe.WriteStrict(pe_IMAGE_FILE_EXECUTABLE_IMAGE | pe_IMAGE_FILE_LINE_NUMS_STRIPPED | pe_IMAGE_FILE_LOCAL_SYMS_STRIPPED | pe_IMAGE_FILE_LARGE_ADDRESS_AWARE | pe_IMAGE_FILE_32BIT_MACHINE | pe_IMAGE_FILE_DEBUG_STRIPPED, Bit16) // Characteristics
}

func (pe *PE) writeOptionalHeader32() { // 224字节。Magic~标准域，ImageBase~NT附加域
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
			pe.WriteRVA("ImportDescriptors") // VirtualAddress
			pe.WriteStrict(40, Bit32) // Size
		}else{
			pe.WriteStrict(0, Bit32) // VirtualAddress
			pe.WriteStrict(0, Bit32) // Size
		}
	}
}

func (pe *PE) writeSectionHeader() error {
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

func (pe *PE) sectionStart() {
	m := pe.Len() % pe_ALIGNMENT_FILE
	if m > 0 {
		pe.WriteSpace(int(pe_ALIGNMENT_FILE - m))
	}
	pe.Label("SectionStart")
}

func (pe *PE) sectionEnd() {
	pe.Label("SectionEnd")
	m := pe.Len() % pe_ALIGNMENT_FILE
	if m > 0 {
		pe.WriteSpace(int(pe_ALIGNMENT_FILE - m))
	}
	pe.Label("SectionAlignEnd")
}

func (pe *PE) ImpBinLibFunc(dll string, function string) {
	pe.imps[dll] = append(pe.imps[dll], function)
}

func (pe *PE) WriteBinlibFuncPtr(function string) {
	pe.WriteVA("Imp.Func." + function)
}

func (pe *PE) writeImportDescriptors() {
	pe.Label("ImportDescriptors")
	for dll, _ := range pe.imps { // 输出 IMAGE_IMPORT_DESCRIPTOR 数组
		pe.WriteRVA("Imp.Lib." + dll + ".Thunk") // OriginalFirstThunk
		pe.WriteStrict(0, Bit32) // TimeDateStamp
		pe.WriteStrict(0, Bit32) // ForwarderChain
		pe.WriteRVA("Imp.Lib." + dll + ".Name") // Name
		pe.WriteRVA("Imp.Lib." + dll + ".Thunk") // FirstThunk
	}
	pe.WriteSpace(pe_IMPORT_DESCRIPTOR_SIZE) // 尾 IMAGE_IMPORT_DESCRIPTOR

	for dll, funcs := range pe.imps {
		pe.Label("Imp.Lib." + dll + ".Name")
		pe.Write(dll)
		pe.Write(byte(0))

		pe.Label("Imp.Lib." + dll + ".Thunk")
		for i := 0; i < len(funcs); i++ {
			pe.Label("Imp.Func." + funcs[i])
			pe.WriteRVA("Imp.Func." + funcs[i] + ".Name")
		}
		pe.WriteSpace(Bit32) // 结尾

		for i := 0; i < len(funcs); i++ {
			pe.Label("Imp.Func." + funcs[i] + ".Name")
			pe.WriteStrict(i, Bit16)
			pe.Write(funcs[i])
			pe.Write(byte(0))
		}
	}
}

const(
	PE_IMAGEBASE_GENERAL = 0x00400000
	pe_RVA_SECTION = 0x00001000
	pe_ALIGNMENT_IMAGE = 0x00001000
	pe_ALIGNMENT_FILE = 0x00000200
	pe_IMPORT_DESCRIPTOR_SIZE = 20

	pe_IMAGE_NT_SIGNATURE = "PE"

	pe_IMAGE_FILE_MACHINE_I386 = 0x014c // x86 CPU
	pe_IMAGE_FILE_MACHINE_IA64 = 0x0200 // x64 CPU

	pe_IMAGE_FILE_RELOCS_STRIPPED = 0x0001 // 文件中不存在重定位信息
	pe_IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002 // 文件是可执行的
	pe_IMAGE_FILE_LINE_NUMS_STRIPPED = 0x0004 // 不存在行信息
	pe_IMAGE_FILE_LOCAL_SYMS_STRIPPED = 0x0008 // 不存在符号信息
	pe_IMAGE_FILE_AGGRESIVE_WS_TRIM = 0x0010 // 让操作系统强制整理工作区
	pe_IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020 // 应用程序可以处理大于2GB的地址空间
//	pe_IMAGE_FILE_??? = 64 // 保留，留以后扩展
	pe_IMAGE_FILE_BYTES_REVERSED_LO = 0x0080 // 小尾方式
	pe_IMAGE_FILE_32BIT_MACHINE = 0x0100 // 只在32位平台上运行
	pe_IMAGE_FILE_DEBUG_STRIPPED = 0x0200 // 不包含调试信息。调试信息位于一个 .DBG 文件中
	pe_IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0x0400 // 如果映像在可移动媒体中，那么复制到交换文件并从交换文件中运行
	pe_IMAGE_FILE_NET_RUN_FROM_SWAP = 0x0800 // 如果映像在网络上，那么复制到交换文件并从交换文件中运行
	pe_IMAGE_FILE_SYSTEM = 0x1000 // 系统文件（如驱动程序），不能直接运行
	pe_IMAGE_FILE_DLL = 0x2000 // 这是一个 DLL 文件
	pe_IMAGE_FILE_UP_SYSTEM_ONLY = 0x4000 // 只能在单处理器机器中运行
	pe_IMAGE_FILE_BYTES_REVERSED_HI = 0x8000 // 大尾方式

	pe_IMAGE_DIRECTORY_ENTRY_EXPORT = 0 // 指向导出表（IMAGE_EXPORT_DIRECTORY）
	pe_IMAGE_DIRECTORY_ENTRY_IMPORT = 1 // 指向导入表（IMAGE_IMPORT_DESCRIPTOR 数组）
	pe_IMAGE_DIRECTORY_ENTRY_RESOURCE = 2 // 指向资源（IMAGE_RESOURCE_DIRECTORY）
	pe_IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3 // 指向异常处理表（IMAGE_RUNTIME_FUNCTION_ENTRY 数组）。CPU特定的并且基于表的异常处理。用于除x86之外的其它CPU上。
	pe_IMAGE_DIRECTORY_ENTRY_SECURITY = 4 // 指向一个 WIN_CERTIFICATE 结构的列表，它定义在 WinTrust.H 中。不会被映射到内存中。因此，VirtualAddress 域是一个文件偏移，而不是一个RVA。
	pe_IMAGE_DIRECTORY_ENTRY_BASERELOC = 5 // 指向基址重定位信息
	pe_IMAGE_DIRECTORY_ENTRY_DEBUG = 6 // 指向一个 IMAGE_DEBUG_DIRECTORY 结构数组，其中每个结构描述了映像的一些调试信息。早期的 Borland 链接器设置这个 IMAGE_DATA_DIRECTORY 结构的 Size 域为结构的数目，而不是字节大小。要得到 IMAGE_DEBUG_DIRECTORY 结构的数目，用 IMAGE_DEBUG_DIRECTORY 的大小除以这个 Size 域
	pe_IMAGE_DIRECTORY_ENTRY_ARCHITECTURE = 7 // 指向特定架构数据，它是一个 IMAGE_ARCHITECTURE_HEADER 结构数组。不用于 x86 或 x64，但看来已用于 DEC/Compaq Alpha。
	pe_IMAGE_DIRECTORY_ENTRY_GLOBALPTR = 8 // 在某些架构体系上 VirtualAddress 域是一个 RVA，被用来作为全局指针（gp）。不用于 x86，而用于 IA-64。Size 域没有被使用。参见2000年11月的 Under The Hood 专栏可得到关于 IA-64 gp 的更多信息
	pe_IMAGE_DIRECTORY_ENTRY_TLS = 9 // 指向线程局部存储初始化节
	pe_IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10 // 指向一个 IMAGE_LOAD_CONFIG_DIRECTORY 结构。IMAGE_LOAD_CONFIG_DIRECTORY 中的信息是特定于 Windows NT、Windows 2000 和 Windows XP 的(例如 GlobalFlag 值)。要把这个结构放到你的可执行文件中，你必须用名字 __load_config_used 定义一个全局结构，类型是 IMAGE_LOAD_CONFIG_DIRECTORY。对于非 x86 的其它体系，符号名是 _load_config_used (只有一个下划线)。如果你确实要包含一个 IMAGE_LOAD_CONFIG_DIRECTORY，那么在 C++ 中要得到正确的名字比较棘手。链接器看到的符号名必须是__load_config_used (两个下划线)。C++ 编译器会在全局符号前加一个下划线。另外，它还用类型信息修饰全局符号名
	pe_IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT = 11 // 指向一个 IMAGE_BOUND_IMPORT_DESCRIPTOR 结构数组，对应于这个映像绑定的每个 DLL。数组元素中的时间戳允许加载器快速判断绑定是否是新的。如果不是，加载器忽略绑定信息并且按正常方式解决导入 API
	pe_IMAGE_DIRECTORY_ENTRY_IAT = 12 // 指向第一个导入地址表（IAT）的开始位置。对应于每个被导入 DLL 的 IAT 都连续地排列在内存中。Size 域指出了所有 IAT 的总的大小。在写入导入函数的地址时加载器使用这个地址和 Size 域指定的大小临时地标记 IAT 为可读写
	pe_IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13 // 指向延迟加载信息，它是一个 CImgDelayDescr 结构数组，定义在 Visual C++ 的头文件 DELAYIMP.H 中。延迟加载的 DLL 直到对它们中的 API 进行第一次调用发生时才会被装入。Windows 中并没有关于延迟加载 DLL 的知识，认识到这一点很重要。延迟加载的特征完全是由链接器和运行时库实现的
	pe_IMAGE_DIRECTORY_ENTRY_COMHEADER = 14 // 它指向可执行文件中 .NET 信息的最高级别信息，包括元数据。这个信息是一个 IMAGE_COR20_HEADER 结构

	pe_IMAGE_SUBSYSTEM_WINDOWS_GUI = 2
	pe_IMAGE_SUBSYSTEM_WINDOWS_CUI = 3

	pe_IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16

	pe_IMAGE_SCN_CNT_CODE = 0x00000020 // 节中包含代码
	pe_IMAGE_SCN_MEM_EXECUTE = 0x20000000 // 节是可执行的
	pe_IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040 // 节中包含已初始化数据
	pe_IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080 // 节中包含未初始化数据
	pe_IMAGE_SCN_MEM_DISCARDABLE = 0x02000000 // 节可被丢弃。用于保存链接器使用的一些信息，包括.debug$节
	pe_IMAGE_SCN_MEM_NOT_PAGED = 0x08000000 // 节不可被页交换，因此它总是存在于物理内存中。经常用于内核模式的驱动程序
	pe_IMAGE_SCN_MEM_SHARED = 0x10000000 // 包含节的数据的物理内存页在所有用到这个可执行体的进程之间共享。因此，每个进程看到这个节中的数据值都是完全一样的。这对一个进程的所有实例之间共享全局变量很有用。要使一个节共享，可使用/section:name,S 链接器选项
	pe_IMAGE_SCN_MEM_READ = 0x40000000 // 节是可读的。几乎总是被设置
	pe_IMAGE_SCN_MEM_WRITE = 0x80000000 // 节是可写的
)