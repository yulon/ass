package ass

const(
	PE_ADDRESS_IMAGE_BASE = 4194304
	PE_ADDRESS_IMAGE_BIN_BASE = 4096

	PE_IMAGE_NT_SIGNATURE = "PE00"

	PE_IMAGE_FILE_RELOCS_STRIPPED = 1 // 文件中不存在重定位信息
	PE_IMAGE_FILE_EXECUTABLE_IMAGE = 2 // 文件是可执行的
	PE_IMAGE_FILE_LINE_NUMS_STRIPPED = 4 // 不存在行信息
	PE_IMAGE_FILE_LOCAL_SYMS_STRIPPED = 8 // 不存在符号信息
	PE_IMAGE_FILE_AGGRESIVE_WS_TRIM = 16 // 让操作系统强制整理工作区
	PE_IMAGE_FILE_LARGE_ADDRESS_AWARE = 32 // 应用程序可以处理大于2GB的地址空间
//	PE_IMAGE_FILE_??? = 64 // 保留，留以后扩展
	PE_IMAGE_FILE_BYTES_REVERSED_LO = 128 // 小尾方式
	PE_IMAGE_FILE_32BIT_MACHINE = 256 // 只在32位平台上运行
	PE_IMAGE_FILE_DEBUG_STRIPPED = 512 // 不包含调试信息。调试信息位于一个 .DBG 文件中
	PE_IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 1024 // 如果映像在可移动媒体中，那么复制到交换文件并从交换文件中运行
	PE_IMAGE_FILE_NET_RUN_FROM_SWAP = 2048 // 如果映像在网络上，那么复制到交换文件并从交换文件中运行
	PE_IMAGE_FILE_SYSTEM = 4096 // 系统文件（如驱动程序），不能直接运行
	PE_IMAGE_FILE_DLL = 8192 // 这是一个 DLL 文件
	PE_IMAGE_FILE_UP_SYSTEM_ONLY = 16384 // 只能在单处理器机器中运行
	PE_IMAGE_FILE_BYTES_REVERSED_HI = 32768 // 大尾方式
	PE_IMAGE_FILE_MACHINE_I386 = 332 // x86 CPU
	PE_IMAGE_FILE_MACHINE_IA64 = 512 // x64 CPU

	PE_IMAGE_DIRECTORY_ENTRY_EXPORT = 0 // 指向导出表（IMAGE_EXPORT_DIRECTORY）
	PE_IMAGE_DIRECTORY_ENTRY_IMPORT = 1 // 指向导入表（IMAGE_IMPORT_DESCRIPTOR 数组）
	PE_IMAGE_DIRECTORY_ENTRY_RESOURCE = 2 // 指向资源（IMAGE_RESOURCE_DIRECTORY）
	PE_IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3 // 指向异常处理表（IMAGE_RUNTIME_FUNCTION_ENTRY 数组）。CPU特定的并且基于表的异常处理。用于除x86之外的其它CPU上。
	PE_IMAGE_DIRECTORY_ENTRY_SECURITY = 4 // 指向一个 WIN_CERTIFICATE 结构的列表，它定义在 WinTrust.H 中。不会被映射到内存中。因此，VirtualAddress 域是一个文件偏移，而不是一个RVA。
	PE_IMAGE_DIRECTORY_ENTRY_BASERELOC = 5 // 指向基址重定位信息
	PE_IMAGE_DIRECTORY_ENTRY_DEBUG = 6 // 指向一个 IMAGE_DEBUG_DIRECTORY 结构数组，其中每个结构描述了映像的一些调试信息。早期的 Borland 链接器设置这个 IMAGE_DATA_DIRECTORY 结构的 Size 域为结构的数目，而不是字节大小。要得到 IMAGE_DEBUG_DIRECTORY 结构的数目，用 IMAGE_DEBUG_DIRECTORY 的大小除以这个 Size 域
	PE_IMAGE_DIRECTORY_ENTRY_ARCHITECTURE = 7 // 指向特定架构数据，它是一个 IMAGE_ARCHITECTURE_HEADER 结构数组。不用于 x86 或 x64，但看来已用于 DEC/Compaq Alpha。
	PE_IMAGE_DIRECTORY_ENTRY_GLOBALPTR = 8 // 在某些架构体系上 VirtualAddress 域是一个 RVA，被用来作为全局指针（gp）。不用于 x86，而用于 IA-64。Size 域没有被使用。参见2000年11月的 Under The Hood 专栏可得到关于 IA-64 gp 的更多信息
	PE_IMAGE_DIRECTORY_ENTRY_TLS = 9 // 指向线程局部存储初始化节
	PE_IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10 // 指向一个 IMAGE_LOAD_CONFIG_DIRECTORY 结构。IMAGE_LOAD_CONFIG_DIRECTORY 中的信息是特定于 Windows NT、Windows 2000 和 Windows XP 的(例如 GlobalFlag 值)。要把这个结构放到你的可执行文件中，你必须用名字 __load_config_used 定义一个全局结构，类型是 IMAGE_LOAD_CONFIG_DIRECTORY。对于非 x86 的其它体系，符号名是 _load_config_used (只有一个下划线)。如果你确实要包含一个 IMAGE_LOAD_CONFIG_DIRECTORY，那么在 C++ 中要得到正确的名字比较棘手。链接器看到的符号名必须是__load_config_used (两个下划线)。C++ 编译器会在全局符号前加一个下划线。另外，它还用类型信息修饰全局符号名
	PE_IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT = 11 // 指向一个 IMAGE_BOUND_IMPORT_DESCRIPTOR 结构数组，对应于这个映像绑定的每个 DLL。数组元素中的时间戳允许加载器快速判断绑定是否是新的。如果不是，加载器忽略绑定信息并且按正常方式解决导入 API
	PE_IMAGE_DIRECTORY_ENTRY_IAT = 12 // 指向第一个导入地址表（IAT）的开始位置。对应于每个被导入 DLL 的 IAT 都连续地排列在内存中。Size 域指出了所有 IAT 的总的大小。在写入导入函数的地址时加载器使用这个地址和 Size 域指定的大小临时地标记 IAT 为可读写
	PE_IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13 // 指向延迟加载信息，它是一个 CImgDelayDescr 结构数组，定义在 Visual C++ 的头文件 DELAYIMP.H 中。延迟加载的 DLL 直到对它们中的 API 进行第一次调用发生时才会被装入。Windows 中并没有关于延迟加载 DLL 的知识，认识到这一点很重要。延迟加载的特征完全是由链接器和运行时库实现的
	PE_IMAGE_DIRECTORY_ENTRY_COMHEADER = 14 // 它指向可执行文件中 .NET 信息的最高级别信息，包括元数据。这个信息是一个 IMAGE_COR20_HEADER 结构

	PE_IMAGE_SUBSYSTEM_WINDOWS_GUI = 2
	PE_IMAGE_SUBSYSTEM_WINDOWS_CUI = 3

	PE_IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16

	PE_IMAGE_SCN_CNT_CODE = 32 // 节中包含代码
	PE_IMAGE_SCN_MEM_EXECUTE = 536870912 // 节是可执行的
	PE_IMAGE_SCN_CNT_INITIALIZED_DATA = 64 // 节中包含已初始化数据
	PE_IMAGE_SCN_CNT_UNINITIALIZED_DATA = 128 // 节中包含未初始化数据
	PE_IMAGE_SCN_MEM_DISCARDABLE = 33554432 // 节可被丢弃。用于保存链接器使用的一些信息，包括.debug$节
	PE_IMAGE_SCN_MEM_NOT_PAGED = 134217728 // 节不可被页交换，因此它总是存在于物理内存中。经常用于内核模式的驱动程序
	PE_IMAGE_SCN_MEM_SHARED = 268435456 // 包含节的数据的物理内存页在所有用到这个可执行体的进程之间共享。因此，每个进程看到这个节中的数据值都是完全一样的。这对一个进程的所有实例之间共享全局变量很有用。要使一个节共享，可使用/section:name,S 链接器选项
	PE_IMAGE_SCN_MEM_READ = 1073741824 // 节是可读的。几乎总是被设置
	PE_IMAGE_SCN_MEM_WRITE = -2147483648 // 节是可写的
)