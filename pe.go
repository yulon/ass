package ass

import (
	"os"
	"strconv"
	"time"
)

type PE struct {
	f *os.File
	l *labeler
	insWriter
	imps    map[string]map[string]func(NumBitOrder)
	datas   map[uint64][]byte
	imgBase int64
	cui     bool
	cpu     uint8
	nbo     NumBitOrder
}

func CreatePE(path string, machine uint8, imageBase int64, console bool) (*PE, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	pe := &PE{
		f:       f,
		l:       newLabeler(f),
		imps:    map[string]map[string]func(NumBitOrder){},
		datas:   map[uint64][]byte{},
		imgBase: imageBase,
		cui:     console,
		cpu:     machine,
	}
	switch pe.cpu {
	case I386:
		pe.insWriter = &i386{
			Writer: f,
			l:      newLabeler(f),
			base:   pe.imgBase + pe_RVA_SECTION,
		}
		pe.nbo = Num32L
	case AMD64:

		pe.nbo = Num64L
	}
	pe.writeDOSHeader()
	pe.writeNTHeader()
	pe.writeSectionHeader()
	pe.sectionStart()
	return pe, nil
}

func (pe *PE) Close() (err error) {
	pe.writeImportDescriptors()
	pe.writeDatas()
	pe.sectionEnd()

	err = pe.insWriter.Close()
	if err != nil {
		pe.f.Close()
		return
	}

	err = pe.l.Close()
	if err != nil {
		pe.f.Close()
		return
	}

	err = pe.f.Close()
	return
}

func (pe *PE) pitRVA(label string, nbo NumBitOrder) {
	pe.l.PitOffset("PE.SectionStart", label, pe_RVA_SECTION, nbo)
}

func (pe *PE) pitVA(label string, nbo NumBitOrder) {
	pe.l.PitOffset("PE.SectionStart", label, pe.imgBase+pe_RVA_SECTION, nbo)
}

func (pe *PE) writeDOSHeader() { // 64字节
	pe.f.Write([]byte("MZ")) // e_magic
	pe.f.Write(Zeros(58))
	pe.l.PitPointer("PE.NTHeaders", Num32L) // e_lfanew
}

func (pe *PE) writeNTHeader() { // 248字节
	pe.l.Label("PE.NTHeaders")
	pe.f.Write(Cstr32("PE"))
	pe.writeFileHeader()
	pe.writeOptionalHeader()
}

func (pe *PE) writeFileHeader() { // 20字节
	switch pe.cpu {
	case I386:
		pe.f.Write(Num16L(pe_IMAGE_FILE_MACHINE_I386)) // Machine
	case AMD64:
		pe.f.Write(Num16L(pe_IMAGE_FILE_MACHINE_AMD64)) // Machine
	}
	pe.f.Write(Num16L(1))                                                                                                                                                                        // NumberOfSections
	pe.f.Write(Num32L(time.Now().Unix()))                                                                                                                                                        // TimeDateStamp
	pe.f.Write(Num32L(0))                                                                                                                                                                        // PointerToSymbolTable
	pe.f.Write(Num32L(0))                                                                                                                                                                        // NumberOfSymbols
	pe.l.PitOffset("PE.OptionalHeaderStart", "PE.OptionalHeaderEnd", 0, Num16L)                                                                                                                  // SizeOfOptionalHeader
	pe.f.Write(Num16L(pe_IMAGE_FILE_EXECUTABLE_IMAGE | pe_IMAGE_FILE_LINE_NUMS_STRIPPED | pe_IMAGE_FILE_LOCAL_SYMS_STRIPPED | pe_IMAGE_FILE_LARGE_ADDRESS_AWARE | pe_IMAGE_FILE_DEBUG_STRIPPED)) // Characteristics
}

func (pe *PE) writeOptionalHeader() {
	pe.l.Label("PE.OptionalHeaderStart")
	switch pe.cpu {
	case I386:
		pe.f.Write(Num16L(pe_IMAGE_NT_OPTIONAL_HDR32_MAGIC)) // Magic
	case AMD64:
		pe.f.Write(Num16L(pe_IMAGE_NT_OPTIONAL_HDR64_MAGIC)) // Magic
	}
	pe.f.Write(Num8(1))                                           // MajorLinkerVersion
	pe.f.Write(Num8(0))                                           // MinerLinkerVersion
	pe.l.PitOffset("PE.SectionStart", "PE.SectionEnd", 0, Num32L) // SizeOfCode
	pe.f.Write(Num32L(0))                                         // SizeOfInitializedData
	pe.f.Write(Num32L(0))                                         // SizeOfUnInitializedData
	pe.f.Write(Num32L(pe_RVA_SECTION))                            // AddressOfEntryPoint
	pe.f.Write(Num32L(pe_RVA_SECTION))                            // BaseOfCode
	if pe.cpu == I386 {
		pe.f.Write(Num32L(pe_RVA_SECTION)) // BaseOfData
	}
	pe.f.Write(pe.nbo(pe.imgBase))                                                  // ImageBase
	pe.f.Write(Num32L(pe_ALIGNMENT_IMAGE))                                          // SectionAlignment
	pe.f.Write(Num32L(pe_ALIGNMENT_FILE))                                           // FileAlignment
	pe.f.Write(Num16L(5))                                                           // MajorOperatingSystemVersion
	pe.f.Write(Num16L(1))                                                           // MinorOperatingSystemVersion
	pe.f.Write(Num16L(0))                                                           // MajorImageVersion
	pe.f.Write(Num16L(0))                                                           // MinorImageVersion
	pe.f.Write(Num16L(5))                                                           // MajorSubsystemVersion
	pe.f.Write(Num16L(1))                                                           // MinorSubsystemVersion
	pe.f.Write(Num32L(0))                                                           // Win32VersionValue
	pe.l.PitOffset("PE.SectionStart", "PE.SectionAlignEnd", pe_RVA_SECTION, Num32L) // SizeOfImage
	pe.l.PitPointer("PE.SectionStart", Num32L)                                      // SizeOfHeaders
	pe.f.Write(Num32L(0))                                                           // CheckSum
	if pe.cui {
		pe.f.Write(Num16L(pe_IMAGE_SUBSYSTEM_WINDOWS_CUI)) // Subsystem
	} else {
		pe.f.Write(Num16L(pe_IMAGE_SUBSYSTEM_WINDOWS_GUI)) // Subsystem
	}
	pe.f.Write(Num16L(0))     // DllCharacteristics
	pe.f.Write(pe.nbo(65536)) // SizeOfStackReserve
	pe.f.Write(pe.nbo(4096))  // SizeOfStackCommit
	pe.f.Write(pe.nbo(65536)) // SizeOfHeapReserve
	pe.f.Write(pe.nbo(4096))  // SizeOfHeapCommit
	pe.f.Write(Num32L(0))     // LoaderFlags
	pe.f.Write(Num32L(16))    // NumberOfRvaAndSizes

	for i := 0; i < 16; i++ {
		// IMAGE_DATA_DIRECTORY
		if i == pe_IMAGE_DIRECTORY_ENTRY_IMPORT {
			pe.pitRVA("PE.ImportDescriptors", Num32L) // VirtualAddress
			pe.f.Write(Num32L(40))                    // Size
		} else {
			pe.f.Write(Num32L(0)) // VirtualAddress
			pe.f.Write(Num32L(0)) // Size
		}
	}
	pe.l.Label("PE.OptionalHeaderEnd")
}

func (pe *PE) writeSectionHeader() error {
	pe.f.Write(Cstr64(".codata"))                                                                                                    // Name
	pe.l.PitOffset("PE.SectionStart", "PE.SectionEnd", 0, Num32L)                                                                    // VirtualSize
	pe.f.Write(Num32L(pe_RVA_SECTION))                                                                                               // VirtualAddress
	pe.l.PitOffset("PE.SectionStart", "PE.SectionAlignEnd", 0, Num32L)                                                               // SizeOfRawData
	pe.l.PitPointer("PE.SectionStart", Num32L)                                                                                       // PointerToRawData
	pe.f.Write(Num32L(0))                                                                                                            // PointerToRelocations
	pe.f.Write(Num32L(0))                                                                                                            // PointerToLinenumbers
	pe.f.Write(Num16L(0))                                                                                                            // NumberOfRelocations
	pe.f.Write(Num16L(0))                                                                                                            // NumberOfLinenumbers
	pe.f.Write(Num32L(pe_IMAGE_SCN_CNT_CODE | pe_IMAGE_SCN_MEM_EXECUTE | pe_IMAGE_SCN_MEM_READ | pe_IMAGE_SCN_CNT_INITIALIZED_DATA)) // Characteristics
	return nil
}

func (pe *PE) sectionStart() {
	fAlign(pe.f, pe_ALIGNMENT_FILE)
	pe.l.Label("PE.SectionStart")
}

func (pe *PE) sectionEnd() {
	pe.l.Label("PE.SectionEnd")
	fAlign(pe.f, pe_ALIGNMENT_FILE)
	pe.l.Label("PE.SectionAlignEnd")
}

func (pe *PE) DLLFuncPtr(dll string, function string) func(NumBitOrder) {
	_, ok := pe.imps[dll]
	if !ok {
		pe.imps[dll] = map[string]func(NumBitOrder){}
		pe.imps[dll][function] = func(nbo NumBitOrder) {
			pe.pitVA("DLLFunc."+dll+"."+function+".Ptr", nbo)
		}
	}
	return pe.imps[dll][function]
}

func (pe *PE) writeImportDescriptors() {
	pe.l.Label("PE.ImportDescriptors")
	for dll, _ := range pe.imps { // 输出 IMAGE_IMPORT_DESCRIPTOR 数组
		pe.pitRVA("DLL."+dll+".Thunk", Num32L) // OriginalFirstThunk
		pe.f.Write(Num32L(0))                  // TimeDateStamp
		pe.f.Write(Num32L(0))                  // ForwarderChain
		pe.pitRVA("DLL."+dll+".Name", Num32L)  // Name
		pe.pitRVA("DLL."+dll+".Thunk", Num32L) // FirstThunk
	}
	pe.f.Write(Zeros(pe_IMPORT_DESCRIPTOR_SIZE)) // 尾 IMAGE_IMPORT_DESCRIPTOR

	for dll, funcs := range pe.imps {
		pe.l.Label("DLL." + dll + ".Name")
		pe.f.Write(Cstr(dll))

		pe.l.Label("DLL." + dll + ".Thunk")
		for function, _ := range funcs {
			pe.l.Label("DLLFunc." + dll + "." + function + ".Ptr")
			pe.pitRVA("DLLFunc."+dll+"."+function+".Name", pe.nbo)
		}
		pe.f.Write(Zeros(int64(pe.cpu))) // 结尾

		i := 0
		for function, _ := range funcs {
			pe.l.Label("DLLFunc." + dll + "." + function + ".Name")
			pe.f.Write(Num16L(i))
			pe.f.Write(Cstr(function))
			i++
		}
	}
}

func (pe *PE) Data(d []byte) func(NumBitOrder) {
	var h uint64
	for i := 0; i < len(d); i++ {
		h = h*31 + uint64(d[i])
	}
	_, ok := pe.datas[h]
	if !ok {
		pe.datas[h] = d
	}
	return func(nbo NumBitOrder) {
		pe.pitVA("Data."+strconv.FormatUint(h, 16), nbo)
	}
}

func (pe *PE) writeDatas() {
	for h, d := range pe.datas {
		pe.l.Label("Data." + strconv.FormatUint(h, 16))
		pe.f.Write(d)
	}
}

const (
	PE_IMAGEBASE_GENERAL      = 0x00400000
	pe_RVA_SECTION            = 0x00001000
	pe_ALIGNMENT_IMAGE        = 0x00001000
	pe_ALIGNMENT_FILE         = 0x00000200
	pe_IMPORT_DESCRIPTOR_SIZE = 20

	pe_IMAGE_FILE_MACHINE_I386  = 0x014c // x86 CPU
	pe_IMAGE_FILE_MACHINE_AMD64 = 0x8664 // x64 CPU

	pe_IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b
	pe_IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b

	pe_IMAGE_FILE_RELOCS_STRIPPED     = 0x0001 // 文件中不存在重定位信息
	pe_IMAGE_FILE_EXECUTABLE_IMAGE    = 0x0002 // 文件是可执行的
	pe_IMAGE_FILE_LINE_NUMS_STRIPPED  = 0x0004 // 不存在行信息
	pe_IMAGE_FILE_LOCAL_SYMS_STRIPPED = 0x0008 // 不存在符号信息
	pe_IMAGE_FILE_AGGRESIVE_WS_TRIM   = 0x0010 // 让操作系统强制整理工作区
	pe_IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020 // 应用程序可以处理大于2GB的地址空间
	//	pe_IMAGE_FILE_??? = 64 // 保留，留以后扩展
	pe_IMAGE_FILE_BYTES_REVERSED_LO       = 0x0080 // 小尾方式
	pe_IMAGE_FILE_32BIT_MACHINE           = 0x0100 // 只在32位平台上运行
	pe_IMAGE_FILE_DEBUG_STRIPPED          = 0x0200 // 不包含调试信息。调试信息位于一个 .DBG 文件中
	pe_IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0x0400 // 如果映像在可移动媒体中，那么复制到交换文件并从交换文件中运行
	pe_IMAGE_FILE_NET_RUN_FROM_SWAP       = 0x0800 // 如果映像在网络上，那么复制到交换文件并从交换文件中运行
	pe_IMAGE_FILE_SYSTEM                  = 0x1000 // 系统文件（如驱动程序），不能直接运行
	pe_IMAGE_FILE_DLL                     = 0x2000 // 这是一个 DLL 文件
	pe_IMAGE_FILE_UP_SYSTEM_ONLY          = 0x4000 // 只能在单处理器机器中运行
	pe_IMAGE_FILE_BYTES_REVERSED_HI       = 0x8000 // 大尾方式

	pe_IMAGE_DIRECTORY_ENTRY_EXPORT       = 0  // 指向导出表（IMAGE_EXPORT_DIRECTORY）
	pe_IMAGE_DIRECTORY_ENTRY_IMPORT       = 1  // 指向导入表（IMAGE_IMPORT_DESCRIPTOR 数组）
	pe_IMAGE_DIRECTORY_ENTRY_RESOURCE     = 2  // 指向资源（IMAGE_RESOURCE_DIRECTORY）
	pe_IMAGE_DIRECTORY_ENTRY_EXCEPTION    = 3  // 指向异常处理表（IMAGE_RUNTIME_FUNCTION_ENTRY 数组）。CPU特定的并且基于表的异常处理。用于除x86之外的其它CPU上。
	pe_IMAGE_DIRECTORY_ENTRY_SECURITY     = 4  // 指向一个 WIN_CERTIFICATE 结构的列表，它定义在 WinTrust.H 中。不会被映射到内存中。因此，VirtualAddress 域是一个文件偏移，而不是一个RVA。
	pe_IMAGE_DIRECTORY_ENTRY_BASERELOC    = 5  // 指向基址重定位信息
	pe_IMAGE_DIRECTORY_ENTRY_DEBUG        = 6  // 指向一个 IMAGE_DEBUG_DIRECTORY 结构数组，其中每个结构描述了映像的一些调试信息。早期的 Borland 链接器设置这个 IMAGE_DATA_DIRECTORY 结构的 Size 域为结构的数目，而不是字节大小。要得到 IMAGE_DEBUG_DIRECTORY 结构的数目，用 IMAGE_DEBUG_DIRECTORY 的大小除以这个 Size 域
	pe_IMAGE_DIRECTORY_ENTRY_ARCHITECTURE = 7  // 指向特定架构数据，它是一个 IMAGE_ARCHITECTURE_HEADER 结构数组。不用于 x86 或 x64，但看来已用于 DEC/Compaq Alpha。
	pe_IMAGE_DIRECTORY_ENTRY_GLOBALPTR    = 8  // 在某些架构体系上 VirtualAddress 域是一个 RVA，被用来作为全局指针（gp）。不用于 x86，而用于 IA-64。Size 域没有被使用。参见2000年11月的 Under The Hood 专栏可得到关于 IA-64 gp 的更多信息
	pe_IMAGE_DIRECTORY_ENTRY_TLS          = 9  // 指向线程局部存储初始化节
	pe_IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG  = 10 // 指向一个 IMAGE_LOAD_CONFIG_DIRECTORY 结构。IMAGE_LOAD_CONFIG_DIRECTORY 中的信息是特定于 Windows NT、Windows 2000 和 Windows XP 的(例如 GlobalFlag 值)。要把这个结构放到你的可执行文件中，你必须用名字 __load_config_used 定义一个全局结构，类型是 IMAGE_LOAD_CONFIG_DIRECTORY。对于非 x86 的其它体系，符号名是 _load_config_used (只有一个下划线)。如果你确实要包含一个 IMAGE_LOAD_CONFIG_DIRECTORY，那么在 C++ 中要得到正确的名字比较棘手。链接器看到的符号名必须是__load_config_used (两个下划线)。C++ 编译器会在全局符号前加一个下划线。另外，它还用类型信息修饰全局符号名
	pe_IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT = 11 // 指向一个 IMAGE_BOUND_IMPORT_DESCRIPTOR 结构数组，对应于这个映像绑定的每个 DLL。数组元素中的时间戳允许加载器快速判断绑定是否是新的。如果不是，加载器忽略绑定信息并且按正常方式解决导入 API
	pe_IMAGE_DIRECTORY_ENTRY_IAT          = 12 // 指向第一个导入地址表（IAT）的开始位置。对应于每个被导入 DLL 的 IAT 都连续地排列在内存中。Size 域指出了所有 IAT 的总的大小。在写入导入函数的地址时加载器使用这个地址和 Size 域指定的大小临时地标记 IAT 为可读写
	pe_IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13 // 指向延迟加载信息，它是一个 CImgDelayDescr 结构数组，定义在 Visual C++ 的头文件 DELAYIMP.H 中。延迟加载的 DLL 直到对它们中的 API 进行第一次调用发生时才会被装入。Windows 中并没有关于延迟加载 DLL 的知识，认识到这一点很重要。延迟加载的特征完全是由链接器和运行时库实现的
	pe_IMAGE_DIRECTORY_ENTRY_COMHEADER    = 14 // 它指向可执行文件中 .NET 信息的最高级别信息，包括元数据。这个信息是一个 IMAGE_COR20_HEADER 结构

	pe_IMAGE_SUBSYSTEM_WINDOWS_GUI = 2
	pe_IMAGE_SUBSYSTEM_WINDOWS_CUI = 3

	pe_IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16

	pe_IMAGE_SCN_CNT_CODE               = 0x00000020 // 节中包含代码
	pe_IMAGE_SCN_MEM_EXECUTE            = 0x20000000 // 节是可执行的
	pe_IMAGE_SCN_CNT_INITIALIZED_DATA   = 0x00000040 // 节中包含已初始化数据
	pe_IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080 // 节中包含未初始化数据
	pe_IMAGE_SCN_MEM_DISCARDABLE        = 0x02000000 // 节可被丢弃。用于保存链接器使用的一些信息，包括.debug$节
	pe_IMAGE_SCN_MEM_NOT_PAGED          = 0x08000000 // 节不可被页交换，因此它总是存在于物理内存中。经常用于内核模式的驱动程序
	pe_IMAGE_SCN_MEM_SHARED             = 0x10000000 // 包含节的数据的物理内存页在所有用到这个可执行体的进程之间共享。因此，每个进程看到这个节中的数据值都是完全一样的。这对一个进程的所有实例之间共享全局变量很有用。要使一个节共享，可使用/section:name,S 链接器选项
	pe_IMAGE_SCN_MEM_READ               = 0x40000000 // 节是可读的。几乎总是被设置
	pe_IMAGE_SCN_MEM_WRITE              = 0x80000000 // 节是可写的
)
