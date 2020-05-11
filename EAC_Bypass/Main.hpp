#pragma once 

#include "ntos.hpp"
#include "ntstructs.hpp"

// Driver stuff

typedef struct HIDEPROC_STRUCT
{
	ULONG pId;
}HIDEPROC_STRUCT, * PHIDEPROC_STRUCT;

typedef struct IS_ENABLED_STRUCT
{
	BOOLEAN IsEnabled;
}IS_ENABLED_STRUCT, * PIS_ENABLED_STRUCT;

typedef struct GETPROC_STRUCT
{
	ULONG pId;
}GETPROC_STRUCT, * PGETPROC_STRUCT;

#define ctl_protectprocess    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xad138, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define ctl_isenabled    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xad136, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define ctl_getprocid    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xad139, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

const WCHAR dNameBuffer[] = L"\\Device\\EAC_Bypass";
const WCHAR dSymLinkBuffer[] = L"\\DosDevices\\EAC_Bypass";
ULONG ProcessIdToProtect = 0;
BOOLEAN IsBypassEnabled = 0;
PDEVICE_OBJECT pDeviceObject = 0;
NTSTATUS DeviceIoHandler(PDEVICE_OBJECT devicDriverObjecte_obj, PIRP IRP);
NTSTATUS DeviceCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS DeviceClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);

// Callbacks
PVOID* ThreadCallBacks = 0, *ImageCallBacks = 0;

// Backups
PVOID ProcessPostOperation = 0, ProcessPreOperation = 0, ThreadPostOperation = 0, ThreadPreOperation = 0, FilterAddr = 0;
PVOID EAC_ThreadRoutine = 0, EAC_ImageRoutine = 0;

// EAC information
PVOID EAC_Base = 0;
ULONG64 EAC_Base_Size = 0;

// Filter information
HANDLE pParentId = 0, pGameId = 0;
LONG lOperationsOffset = 0;

typedef NTSTATUS(NTAPI* p_PsSuspendThread)(IN PETHREAD Thread, OUT PULONG PreviousCount OPTIONAL);
p_PsSuspendThread o_PsSuspendThread = 0;

typedef NTSTATUS(NTAPI* p_PsResumeThread)(IN PETHREAD Thread);
p_PsResumeThread o_PsResumeThread = 0;

// Bypass functions
BOOLEAN RestoreImageCallBack();
BOOLEAN RestoreThreadCallBack();

// Routines
VOID ImageRoutine(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO Info);
VOID ProcessRoutine(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create);


// Utils
NTSTATUS SearchPattern(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound);
PVOID GetKernelBase();
BOOLEAN IsFromEACRange(PVOID Address);
BOOLEAN SuspendOrResumeAllThreads(BOOLEAN Suspend);
uintptr_t dereference(uintptr_t address, unsigned int offset);
VOID HideDriver(PDRIVER_OBJECT pDriverObject);

