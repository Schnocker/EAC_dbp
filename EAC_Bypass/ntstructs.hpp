#pragma once

typedef struct _OPERATION_INFO_ENTRY
{
	LIST_ENTRY    ListEntry;
	OB_OPERATION  Operation;
	ULONG         Flags;
	PVOID         Object;
	POBJECT_TYPE  ObjectType;
	ACCESS_MASK   AccessMask;
} OPERATION_INFO_ENTRY, * POPERATION_INFO_ENTRY;


typedef struct _THREAD_BASIC_INFORMATION
{
	NTSTATUS                ExitStatus;
	PVOID                   TebBaseAddress;
	CLIENT_ID               ClientId;
	KAFFINITY               AffinityMask;
	KPRIORITY               Priority;
	KPRIORITY               BasePriority;
} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;


typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _SYSTEM_THREAD {
	LARGE_INTEGER           KernelTime;
	LARGE_INTEGER           UserTime;
	LARGE_INTEGER           CreateTime;
	ULONG                   WaitTime;
	PVOID                   StartAddress;
	CLIENT_ID               ClientId;
	KPRIORITY               Priority;
	LONG                    BasePriority;
	ULONG                   ContextSwitchCount;
	ULONG                   State;
	KWAIT_REASON            WaitReason;
} SYSTEM_THREAD, * PSYSTEM_THREAD;

typedef struct _SYSTEM_THREAD_INFORMATION
{
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	LONG BasePriority;
	ULONG ContextSwitches;
	ULONG ThreadState;
	KWAIT_REASON WaitReason;
} SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER WorkingSetPrivateSize; // since VISTA
	ULONG HardFaultCount; // since WIN7
	ULONG NumberOfThreadsHighWatermark; // since WIN7
	ULONGLONG CycleTime; // since WIN7
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR UniqueProcessKey; // since VISTA (requires SystemExtendedProcessInformation)
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
	SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[ANYSIZE_ARRAY];
}RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

typedef struct _IMAGE_SECTION_HEADER {
	char  Name[8];
	union {
		ULONG PhysicalAddress;
		ULONG VirtualSize;
	} Misc;
	ULONG VirtualAddress;
	ULONG SizeOfRawData;
	ULONG PointerToRawData;
	ULONG PointerToRelocations;
	ULONG PointerToLinenumbers;
	WORD  NumberOfRelocations;
	WORD  NumberOfLinenumbers;
	ULONG Characteristics;
} IMAGE_SECTION_HEADER, * PIMAGE_SECTION_HEADER;

typedef struct _IMAGE_FILE_HEADER {
	WORD  Machine;
	WORD  NumberOfSections;
	ULONG TimeDateStamp;
	ULONG PointerToSymbolTable;
	ULONG NumberOfSymbols;
	WORD  SizeOfOptionalHeader;
	WORD  Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
	ULONG VirtualAddress;
	ULONG Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
	WORD        Magic;
	char        MajorLinkerVersion;
	char        MinorLinkerVersion;
	ULONG       SizeOfCode;
	ULONG       SizeOfInitializedData;
	ULONG       SizeOfUninitializedData;
	ULONG       AddressOfEntryPoint;
	ULONG       BaseOfCode;
	ULONGLONG   ImageBase;
	ULONG       SectionAlignment;
	ULONG       FileAlignment;
	WORD        MajorOperatingSystemVersion;
	WORD        MinorOperatingSystemVersion;
	WORD        MajorImageVersion;
	WORD        MinorImageVersion;
	WORD        MajorSubsystemVersion;
	WORD        MinorSubsystemVersion;
	ULONG       Win32VersionValue;
	ULONG       SizeOfImage;
	ULONG       SizeOfHeaders;
	ULONG       CheckSum;
	WORD        Subsystem;
	WORD        DllCharacteristics;
	ULONGLONG   SizeOfStackReserve;
	ULONGLONG   SizeOfStackCommit;
	ULONGLONG   SizeOfHeapReserve;
	ULONGLONG   SizeOfHeapCommit;
	ULONG       LoaderFlags;
	ULONG       NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64 {
	ULONG                   Signature;
	IMAGE_FILE_HEADER       FileHeader;
	IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;


typedef struct _OBJECT_TYPE_INITIALIZER
{
	SHORT Length;
	UCHAR ObjectTypeFlags;
	ULONG CaseInsensitive : 1;
	ULONG UnnamedObjectsOnly : 1;
	ULONG UseDefaultObject : 1;
	ULONG SecurityRequired : 1;
	ULONG MaintainHandleCount : 1;
	ULONG MaintainTypeList : 1;
	ULONG ObjectTypeCode;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccessMask;
	POOL_TYPE PoolType;
	ULONG DefaultPagedPoolCharge;
	ULONG DefaultNonPagedPoolCharge;
	PVOID DumpProcedure;
	LONG* OpenProcedure;
	PVOID CloseProcedure;
	PVOID DeleteProcedure;
	LONG* ParseProcedure;
	LONG* SecurityProcedure;
	LONG* QueryNameProcedure;
	UCHAR* OkayToCloseProcedure;
} OBJECT_TYPE_INITIALIZER, * POBJECT_TYPE_INITIALIZER;

typedef struct _CALLBACK_ENTRY {
	UINT16 Version;
	UINT16 OperationRegistrationCount;
	UINT32 unk1;
	PVOID RegistrationContext;
	UNICODE_STRING Altitude;
} CALLBACK_ENTRY, * PCALLBACK_ENTRY;

typedef struct _CALLBACK_ENTRY_ITEM {
	LIST_ENTRY EntryItemList;
	OB_OPERATION Operations;
	CALLBACK_ENTRY* CallbackEntry;
	POBJECT_TYPE ObjectType;
	POB_PRE_OPERATION_CALLBACK PreOperation;
	POB_POST_OPERATION_CALLBACK PostOperation;
	__int64 unk;
}CALLBACK_ENTRY_ITEM, * PCALLBACK_ENTRY_ITEM;

typedef struct _OBJECT_TYPE {
	LIST_ENTRY TypeList;
	UNICODE_STRING Name;
	VOID* DefaultObject;
	UCHAR Index;
	unsigned __int32 TotalNumberOfObjects;
	unsigned __int32 TotalNumberOfHandles;
	unsigned __int32 HighWaterNumberOfObjects;
	unsigned __int32 HighWaterNumberOfHandles;
	OBJECT_TYPE_INITIALIZER TypeInfo;
	EX_PUSH_LOCK TypeLock;
	unsigned __int32 Key;
	LIST_ENTRY CallbackList;
}OBJECT_TYPE, * POBJECT_TYPE;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union
	{
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	struct _ACTIVATION_CONTEXT* EntryPointActivationContext;
	PVOID PatchInformation;
	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;