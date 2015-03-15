package ass

const(
	PE_ADDRESS_IMAGE_BASE = 4194304
	PE_ADDRESS_RVA_BASE = 4096

	PE_IMAGE_NT_SIGNATURE = 17744
	PE_IMAGE_FILE_RELOCS_STRIPPED = 1 // 文件中不存在重定位信息
	PE_IMAGE_FILE_EXECUTABLE_IMAGE = 2 // 文件是可执行的
	PE_IMAGE_FILE_LINE_NUMS_STRIPPED = 4 // 不存在行信息
	PE_IMAGE_FILE_LOCAL_SYMS_STRIPPED = 8 // 不存在符号信息
	PE_IMAGE_FILE_AGGRESIVE_WS_TRIM = 16 // 被舍弃，值为“0”
	PE_IMAGE_FILE_LARGE_ADDRESS_AWARE = 32 // 应用程序可以处理大于2GB的地址空间
//	PE_IMAGE_FILE_??? = 64 // 保留，留以后扩展
	PE_IMAGE_FILE_BYTES_REVERSED_LO = 128 // 小尾方式
	PE_IMAGE_FILE_32BIT_MACHINE = 256 // 只在32位平台上运行
	PE_IMAGE_FILE_DEBUG_STRIPPED = 512 // 不包含调试信息
	PE_IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 1024 // 不能从可移动盘（如软盘、光盘）运行
	PE_IMAGE_FILE_NET_RUN_FROM_SWAP = 2048 // 不能从网络运行
	PE_IMAGE_FILE_SYSTEM = 4096 // 系统文件（如驱动程序），不能直接运行
	PE_IMAGE_FILE_DLL = 8192 // 这是一个DLL文件
	PE_IMAGE_FILE_UP_SYSTEM_ONLY = 16384 // 文件不能在多处理器上计算机上运行
	PE_IMAGE_FILE_BYTES_REVERSED_HI = 32768 // 大尾方式
	PE_IMAGE_DIRECTORY_ENTRY_EXPORT = 0 // 导出表
	PE_IMAGE_DIRECTORY_ENTRY_IMPORT = 1 // 导入表
	PE_IMAGE_DIRECTORY_ENTRY_RESOURCE = 2 // 资源
	PE_IMAGE_DIRECTORY_ENTRY_BASERELOC = 5 // 重定位表
	PE_IMAGE_DIRECTORY_ENTRY_DEBUG = 6 // 调试信息
	PE_IMAGE_DIRECTORY_ENTRY_ARCHITECTURE = 7 // 版权信息
	PE_IMAGE_DIRECTORY_ENTRY_IAT = 12 // 导入函数地址表
	PE_IMAGE_SUBSYSTEM_WINDOWS_GUI = 2
	PE_IMAGE_SUBSYSTEM_WINDOWS_CUI = 3
	PE_IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16
	PE_IMAGE_FILE_MACHINE_I386 = 332
)