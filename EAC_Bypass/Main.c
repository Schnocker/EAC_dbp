#include "main.hpp"
#include "Options.hpp"

#pragma region CallBacks
OB_PREOP_CALLBACK_STATUS ProcessObjectPreCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation)
{
	UNREFERENCED_PARAMETER(RegistrationContext);
	VirtualizerStart();
	VirtualizerStrEncryptStart();
#if (PROTECT_PROCESS == 1)
	if (OperationInformation && MmIsAddressValid(OperationInformation))
	{
		HANDLE pid = PsGetProcessId((PEPROCESS)OperationInformation->Object);
		if (pid && pid == (HANDLE)ProcessIdToProtect)
		{
			if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE ||
				OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
			{
				if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_TERMINATE) == PROCESS_TERMINATE)
				{
					OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
				}
				if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_OPERATION) == PROCESS_VM_OPERATION)
				{
					OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;
				}
				if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_READ) == PROCESS_VM_READ)
				{
					OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;
				}
				if ((OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_WRITE) == PROCESS_VM_WRITE)
				{
					OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;
				}
			}
		}
	}
#endif
	VirtualizerStrEncryptEnd();
	VirtualizerEnd();
	if (PsGetCurrentProcessId() == 4)
	{
		POB_PRE_OPERATION_CALLBACK EACCallBack = (POB_PRE_OPERATION_CALLBACK)ProcessPreOperation;
		EACCallBack(RegistrationContext, OperationInformation);
	}
	if (PsGetCurrentProcessId() == pGameId)
	{
		POB_PRE_OPERATION_CALLBACK EACCallBack = (POB_PRE_OPERATION_CALLBACK)ProcessPreOperation;
		EACCallBack(RegistrationContext, OperationInformation);
	}
	return(OB_PREOP_SUCCESS);
}

VOID ProcessObjectPostCallback(PVOID RegistrationContext, POB_POST_OPERATION_INFORMATION OperationInformation)
{
	if (PsGetCurrentProcessId() == 4)
	{
		POB_POST_OPERATION_CALLBACK EACCallBack = (POB_POST_OPERATION_CALLBACK)ProcessPostOperation;
		EACCallBack(RegistrationContext, OperationInformation);
	}
	if (PsGetCurrentProcessId() == pGameId)
	{
		POB_POST_OPERATION_CALLBACK EACCallBack = (POB_POST_OPERATION_CALLBACK)ProcessPostOperation;
		EACCallBack(RegistrationContext, OperationInformation);
	}
	return;
}

OB_PREOP_CALLBACK_STATUS ThreadObjectPreCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation)
{
	if (PsGetCurrentProcessId() == 4)
	{
		POB_PRE_OPERATION_CALLBACK EACCallBack = (POB_PRE_OPERATION_CALLBACK)ThreadPreOperation;
		EACCallBack(RegistrationContext, OperationInformation);
	}
	
	return(OB_PREOP_SUCCESS);
}

VOID ThreadObjectPostCallback(PVOID RegistrationContext, POB_POST_OPERATION_INFORMATION OperationInformation)
{
	if (PsGetCurrentProcessId() == 4)
	{
		POB_POST_OPERATION_CALLBACK EACCallBack = (POB_POST_OPERATION_CALLBACK)ThreadPostOperation;
		EACCallBack(RegistrationContext, OperationInformation);
	}
	return;
}

// credits for this function and the offsets goes to https://www.write-bug.com/article/2503.html
BOOLEAN RemoveMiniFilter()
{
#if (REMOVE_FILTER == 1)
	VirtualizerStart();
	VirtualizerStrEncryptStart();
	NTSTATUS status = STATUS_SUCCESS;
	ULONG ulFilterListSize = 0;
	PFLT_FILTER* ppFilterList = NULL;
	ULONG i = 0;
	PFLT_OPERATION_REGISTRATION pFltOperationRegistration = NULL;
	FltEnumerateFilters(NULL, 0, &ulFilterListSize);
	ppFilterList = (PFLT_FILTER*)ExAllocatePool(NonPagedPool, ulFilterListSize * sizeof(PFLT_FILTER));
	if (NULL == ppFilterList)
	{
		DbgPrint("[EAC_Bypass] ExAllocatePool Error!\n");
		return FALSE;
	}
	status = FltEnumerateFilters(ppFilterList, ulFilterListSize, &ulFilterListSize);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[EAC_Bypass] FltEnumerateFilters Error![0x%X]\n", status);
		return FALSE;
	}
	DbgPrint("[EAC_Bypass] ulFilterListSize=%d\n", ulFilterListSize);
	if (lOperationsOffset == 0)
	{
		DbgPrint("[EAC_Bypass] GetOperationsOffset Error\n");
		return FALSE;
	}
	try
	{
		for (i = 0; i < ulFilterListSize; i++)
		{
			pFltOperationRegistration = (PFLT_OPERATION_REGISTRATION)(*(PVOID*)((PUCHAR)ppFilterList[i] + lOperationsOffset));
			try
			{
				while (IRP_MJ_OPERATION_END != pFltOperationRegistration->MajorFunction)
				{
					if (MmIsAddressValid(pFltOperationRegistration->PreOperation) &&
						IsFromEACRange(pFltOperationRegistration->PreOperation))
					{
						FilterAddr = pFltOperationRegistration->PreOperation;
						pFltOperationRegistration->PreOperation = DummyObjectPreCallback;
						DbgPrint("[EAC_Bypass] BE Filter found 0x%llX", FilterAddr);
						break;
					}
					pFltOperationRegistration = (PFLT_OPERATION_REGISTRATION)((PUCHAR)pFltOperationRegistration + sizeof(FLT_OPERATION_REGISTRATION));
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				DbgPrint("[EAC_Bypass] Exception [0x%X] in RemoveMiniFilter", GetExceptionCode());
			}
			FltObjectDereference(ppFilterList[i]);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint("[EAC_Bypass] Exception [0x%X] in RemoveMiniFilter", GetExceptionCode());
	}
	VirtualizerStrEncryptEnd();
	VirtualizerEnd();
	ExFreePool(ppFilterList);
	ppFilterList = NULL;
#endif
	return TRUE;
}

BOOLEAN RestoreMiniFilter()
{
#if (REMOVE_FILTER == 1)
	NTSTATUS status = STATUS_SUCCESS;
	ULONG ulFilterListSize = 0;
	PFLT_FILTER* ppFilterList = NULL;
	ULONG i = 0;
	PFLT_OPERATION_REGISTRATION pFltOperationRegistration = NULL;
	try
	{
		VirtualizerStart();
		VirtualizerStrEncryptStart();
		FltEnumerateFilters(NULL, 0, &ulFilterListSize);
		ppFilterList = (PFLT_FILTER*)ExAllocatePool(NonPagedPool, ulFilterListSize * sizeof(PFLT_FILTER));
		if (NULL == ppFilterList)
		{
			DbgPrint("[EAC_Bypass] ExAllocatePool Error!\n");
			return FALSE;
		}
		status = FltEnumerateFilters(ppFilterList, ulFilterListSize, &ulFilterListSize);
		if (!NT_SUCCESS(status))
		{
			DbgPrint("[EAC_Bypass] FltEnumerateFilters Error![0x%X]\n", status);
			return FALSE;
		}
		DbgPrint("[EAC_Bypass] ulFilterListSize=%d\n", ulFilterListSize);
		if (lOperationsOffset == 0)
		{
			DbgPrint("[EAC_Bypass] GetOperationsOffset Error\n");
			return FALSE;
		}
		for (i = 0; i < ulFilterListSize; i++)
		{
			pFltOperationRegistration = (PFLT_OPERATION_REGISTRATION)(*(PVOID*)((PUCHAR)ppFilterList[i] + lOperationsOffset));
			try
			{
				while (IRP_MJ_OPERATION_END != pFltOperationRegistration->MajorFunction)
				{
					if (pFltOperationRegistration->PreOperation == DummyObjectPreCallback)
					{
						pFltOperationRegistration->PreOperation = pFltOperationRegistration->PreOperation;
						DbgPrint("[EAC_Bypass] EAC Filter restored");
					}
					pFltOperationRegistration = (PFLT_OPERATION_REGISTRATION)((PUCHAR)pFltOperationRegistration + sizeof(FLT_OPERATION_REGISTRATION));
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				DbgPrint("[EAC_Bypass] Exception [0x%X] in RemoveMiniFilter", GetExceptionCode());
			}
			FltObjectDereference(ppFilterList[i]);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint("[EAC_Bypass] Exception [0x%X] in RemoveMiniFilter", GetExceptionCode());
	}
	VirtualizerStrEncryptEnd();
	VirtualizerEnd();

	ExFreePool(ppFilterList);
	ppFilterList = NULL;
#endif
	return TRUE;
}

BOOLEAN Do_Bypass()
{
	PLIST_ENTRY FirstEntry = 0;
	PLIST_ENTRY pEntry = 0;;
	__try
	{
		VirtualizerStart();
		VirtualizerStrEncryptStart();
#if (REMOVE_PROCESSCALLBACKS == 1)
		if (ProcessPostOperation || ProcessPreOperation)
			return TRUE;
#if (SUSPEND_EAC == 1)
		if (!NT_SUCCESS(SuspendOrResumeAllThreads(1)))
		{
			DbgPrint("[EAC_Bypass] SuspendOrResumeAllThreads failed.");
			return FALSE;
		}
#endif
		FirstEntry = (PLIST_ENTRY)((uintptr_t)* PsProcessType + 0xC8);
		pEntry = FirstEntry;
		while (pEntry != NULL || pEntry != FirstEntry)
		{
			CALLBACK_ENTRY_ITEM* curCallback = (CALLBACK_ENTRY_ITEM*)pEntry;
			if (!MmIsAddressValid(pEntry))
				break;
			if (IsFromEACRange((PVOID)curCallback->PostOperation) ||
				IsFromEACRange((PVOID)curCallback->PreOperation))
			{
				ProcessPostOperation = (PVOID)curCallback->PostOperation;
				ProcessPreOperation = (PVOID)curCallback->PreOperation;
				curCallback->PostOperation = (POB_POST_OPERATION_CALLBACK)ProcessObjectPostCallback;
				curCallback->PreOperation = (POB_PRE_OPERATION_CALLBACK)ProcessObjectPreCallback;
				break;
			}
			pEntry = pEntry->Flink;
			if (pEntry == FirstEntry || pEntry == 0 || !MmIsAddressValid(pEntry) || !MmIsAddressValid(pEntry)) break;
		}
#endif
#if (REMOVE_THREADCALLBACKS == 1)
		FirstEntry = (PLIST_ENTRY)((uintptr_t)* PsThreadType + 0xC8);
		pEntry = FirstEntry;
		while (pEntry != NULL || pEntry != FirstEntry)
		{
			CALLBACK_ENTRY_ITEM* curCallback = (CALLBACK_ENTRY_ITEM*)pEntry;
			if (!MmIsAddressValid(pEntry))
				break;
			if (IsFromEACRange((PVOID)curCallback->PostOperation) ||
				IsFromEACRange((PVOID)curCallback->PreOperation))
			{
				ThreadPostOperation = (PVOID)curCallback->PostOperation;
				ThreadPreOperation = (PVOID)curCallback->PreOperation;
				curCallback->PostOperation = (POB_POST_OPERATION_CALLBACK)ThreadObjectPostCallback;
				curCallback->PreOperation = (POB_PRE_OPERATION_CALLBACK)ThreadObjectPreCallback;
				break;
			}
			pEntry = pEntry->Flink;
			if (pEntry == FirstEntry || pEntry == 0 || !MmIsAddressValid(pEntry) || !MmIsAddressValid(pEntry)) break;
		}
#endif
		VirtualizerStrEncryptEnd();
		VirtualizerEnd();
	}
	except(EXCEPTION_EXECUTE_HANDLER)
	{
		VirtualizerStrEncryptStart();
		DbgPrint("[EAC_Bypass] Exception [0x%X] in Do_Bypass", GetExceptionCode());
		VirtualizerStrEncryptEnd();
		return FALSE;
	}
	return TRUE;
}

BOOLEAN Remove_Bypass()
{
	PLIST_ENTRY FirstEntry = 0;
	PLIST_ENTRY pEntry = 0;
	__try
	{
		VirtualizerStart();
		VirtualizerStrEncryptStart();
#if (REMOVE_PROCESSCALLBACKS == 1)
		FirstEntry = (PLIST_ENTRY)((uintptr_t)* PsProcessType + 0xC8);
		pEntry = FirstEntry;
		while (pEntry != NULL || pEntry != FirstEntry)
		{
			CALLBACK_ENTRY_ITEM* curCallback = (CALLBACK_ENTRY_ITEM*)pEntry;
			if (!MmIsAddressValid(pEntry))
				break;
			if (curCallback->PostOperation == ProcessObjectPostCallback ||
				curCallback->PreOperation == ProcessObjectPreCallback)
			{
				curCallback->PostOperation = (POB_POST_OPERATION_CALLBACK)ProcessPostOperation;
				curCallback->PreOperation = (POB_PRE_OPERATION_CALLBACK)ProcessPreOperation;
				ProcessPostOperation = 0;
				ProcessPreOperation = 0;
				break;
			}
			pEntry = pEntry->Flink;
			if (pEntry == FirstEntry || pEntry == 0 || !MmIsAddressValid(pEntry)) break;
		}
#endif
#if (REMOVE_THREADCALLBACKS == 1)
		FirstEntry = (PLIST_ENTRY)((uintptr_t)* PsThreadType + 0xC8);
		pEntry = FirstEntry;
		while (pEntry != NULL || pEntry != FirstEntry)
		{
			CALLBACK_ENTRY_ITEM* curCallback = (CALLBACK_ENTRY_ITEM*)pEntry;
			if (!MmIsAddressValid(pEntry))
				break;
			if (curCallback->PostOperation == ThreadObjectPostCallback ||
				curCallback->PreOperation == ThreadObjectPreCallback)
			{
				curCallback->PostOperation = (POB_POST_OPERATION_CALLBACK)ThreadPostOperation;
				curCallback->PreOperation = (POB_PRE_OPERATION_CALLBACK)ThreadPreOperation;
				ThreadPostOperation = 0;
				ThreadPreOperation = 0;
				break;
			}
			pEntry = pEntry->Flink;
			if (pEntry == FirstEntry || pEntry == 0 || !MmIsAddressValid(pEntry)) break;
		}
#endif
#if (SUSPEND_EAC == 1)
		if (!NT_SUCCESS(SuspendOrResumeAllThreads(0)))
		{
			DbgPrint("[EAC_Bypass] SuspendOrResumeAllThreads failed.");
			return FALSE;
		}
#endif
		VirtualizerStrEncryptEnd();
		VirtualizerEnd();
	}
	except(EXCEPTION_EXECUTE_HANDLER)
	{
		VirtualizerStrEncryptStart();
		DbgPrint("[EAC_Bypass] Exception [0x%X] in Remove_Bypass", GetExceptionCode());
		VirtualizerStrEncryptEnd();
		return FALSE;
	}
	return TRUE;
}

BOOLEAN FuckImageCallBack()
{
#if (REMOVE_IMAGEROUTINE == 1)
	__try
	{
		VirtualizerStart();
		VirtualizerStrEncryptStart();
		ULONG64	NotifyAddr = 0, MagicPtr = 0;
		ULONG64	PspLoadImageNotifyRoutine = (ULONG64)ImageCallBacks;
		for (int i = 0; i < 64; i++)
		{
			MagicPtr = PspLoadImageNotifyRoutine + i * 8;
			NotifyAddr = *(PULONG64)(MagicPtr);
			if (MmIsAddressValid((PVOID)NotifyAddr) && NotifyAddr != 0)
			{
				NotifyAddr = *(PULONG64)(NotifyAddr & 0xfffffffffffffff8);
				if (IsFromEACRange((PVOID)NotifyAddr))
				{
					DbgPrint("[EAC_Bypass] EAC found in ImageCallBacks");
					EAC_ImageRoutine = (PVOID)NotifyAddr;
					if (!NT_SUCCESS(PsRemoveLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)NotifyAddr)))
						DbgPrint("[EAC_Bypass] PsRemoveLoadImageNotifyRoutine failed");
					else
					{
						DbgPrint("[EAC_Bypass] ImageCallBack has been removed");
						return TRUE;
					}
				}
			}
		}
		VirtualizerStrEncryptEnd();
		VirtualizerEnd();
	}
	except(EXCEPTION_EXECUTE_HANDLER)
	{
		VirtualizerStrEncryptStart();
		DbgPrint("[EAC_Bypass] Exception [0x%X] in FuckImageCallBack", GetExceptionCode());
		VirtualizerStrEncryptEnd();
		return FALSE;
	}
#endif
	return FALSE;
}

BOOLEAN FuckThreadCallBack()
{
#if (REMOVE_THREADROUTINE == 1)
	__try
	{
		VirtualizerStart();
		VirtualizerStrEncryptStart();
		ULONG64	NotifyAddr = 0, MagicPtr = 0;
		ULONG64	PspCreateThreadNotifyRoutine = (ULONG64)ThreadCallBacks;
		for (int i = 0; i < 64; i++)
		{
			MagicPtr = PspCreateThreadNotifyRoutine + i * 8;
			NotifyAddr = *(PULONG64)(MagicPtr);
			if (MmIsAddressValid((PVOID)NotifyAddr) && NotifyAddr != 0)
			{
				NotifyAddr = *(PULONG64)(NotifyAddr & 0xfffffffffffffff8);
				if (IsFromEACRange((PVOID)NotifyAddr))
				{
					DbgPrint("[EAC_Bypass] EAC found in ThreadCallBacks");
					EAC_ThreadRoutine = (PVOID)NotifyAddr;
					if (!NT_SUCCESS(PsRemoveCreateThreadNotifyRoutine((PCREATE_THREAD_NOTIFY_ROUTINE)NotifyAddr)))
						DbgPrint("[EAC_Bypass] PsRemoveCreateThreadNotifyRoutine failed");
					else
					{
						DbgPrint("[EAC_Bypass] ThreadCallBack has been removed");
						return TRUE;
					}
				}
			}
		}
		VirtualizerStrEncryptEnd();
		VirtualizerEnd();
	}
	except(EXCEPTION_EXECUTE_HANDLER)
	{
		VirtualizerStrEncryptStart();
		DbgPrint("[EAC_Bypass] Exception [0x%X] in FuckThreadCallBack", GetExceptionCode());
		VirtualizerStrEncryptEnd();
		return FALSE;
	}
#endif

	return FALSE;
}

BOOLEAN RestoreImageCallBack()
{
	VirtualizerStart();
	VirtualizerStrEncryptStart();
#if (REMOVE_IMAGEROUTINE == 1)
	if (!MmIsAddressValid((PVOID)EAC_ImageRoutine) ||
		!NT_SUCCESS(PsSetLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)EAC_ImageRoutine)))
		DbgPrint("[EAC_Bypass] WARNING : PsSetLoadImageNotifyRoutine failed");
	else
	{
		DbgPrint("[EAC_Bypass] ImageCallBack has been restored");
		return TRUE;
	}
#endif
	VirtualizerStrEncryptEnd();
	VirtualizerEnd();
	return FALSE;
}

BOOLEAN RestoreThreadCallBack()
{
	VirtualizerStart();
	VirtualizerStrEncryptStart();
#if (REMOVE_THREADROUTINE == 1)
	if (!MmIsAddressValid((PVOID)EAC_ThreadRoutine) ||
		!NT_SUCCESS(PsSetCreateThreadNotifyRoutine((PCREATE_THREAD_NOTIFY_ROUTINE)EAC_ThreadRoutine)))
		DbgPrint("[EAC_Bypass] WARNING : PsSetCreateThreadNotifyRoutine failed");
	else
	{
		DbgPrint("[EAC_Bypass] ThreadCallBack has been restored");
		return TRUE;
	}
#endif
	VirtualizerStrEncryptEnd();
	VirtualizerEnd();
	return FALSE;
}

#pragma endregion CallBacks

#pragma region Routines
VOID ImageRoutine(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO Info)
{
	UNREFERENCED_PARAMETER(ProcessId);
	//VirtualizerStart();
	if (wcsstr(FullImageName->Buffer, L"EasyAntiCheat.sys"))
	{
		EAC_Base = Info->ImageBase;
		EAC_Base_Size = Info->ImageSize;
		VirtualizerStrEncryptStart();
		DbgPrint("[EAC_Bypass] EAC found in ImageRoutine 0x%llX %d", EAC_Base, EAC_Base_Size);
		VirtualizerStrEncryptEnd();
	}
	//VirtualizerEnd();
}

VOID ProcessRoutine(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create)
{
	VirtualizerStart();
	VirtualizerStrEncryptStart();
	LPSTR lpFileName = 0;
	PEPROCESS Process = 0;
	if (ProcessId == pGameId && pGameId)
	{
		if (Create == 0)
		{
			DbgPrint("[EAC_Bypass] Protected process %d close %I64x %I64x", ProcessId, EAC_Base, EAC_Base_Size);
			if (ProcessPreOperation || ProcessPostOperation || ThreadPreOperation || ThreadPostOperation)
			{

				if (Remove_Bypass() == FALSE)
					DbgPrint("[EAC_Bypass] WARNING : Remove_Bypass failed");
			}
			IsBypassEnabled = FALSE;
			if (FilterAddr)
			{
				if (!RestoreMiniFilter())
					DbgPrint("[EAC_Bypass] WARNING : RestoreMiniFilter failed");
			}
#if (RESTORE_ROUTINES == 1)
			/*if (RestoreThreadCallBack() == FALSE)
				DbgPrint("[EAC_Bypass] WARNING : RestoreImageCallBack failed.");
			if (RestoreImageCallBack() == FALSE)
				DbgPrint("[EAC_Bypass] WARNING : RestoreImageCallBack failed.");*/
#endif
		}
	}
	// This is required to make sure we don't disturb the game launch
	if (ProcessId == pParentId && pParentId)
	{
		if (Create == 0)
		{
			DbgPrint("[EAC_Bypass] Protected launcher %d close %I64x %I64x", ProcessId);
			if (FuckImageCallBack() == FALSE)
				DbgPrint("[EAC_Bypass] WARNING : FuckImageCallBack failed");
			if (FuckThreadCallBack() == FALSE)
				DbgPrint("[EAC_Bypass] WARNING : FuckThreadCallBack failed");
			if (!RemoveMiniFilter())
				DbgPrint("[EAC_Bypass] WARNING : RemoveMiniFilter failed");
		}
	}
	if (!NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process)))
	{
		DbgPrint("[EAC_Bypass] WARNING : PsLookupProcessByProcessId failed");
		return;
	}
	if (MmIsAddressValid(Process))
	{
		lpFileName = (LPSTR)PsGetProcessImageFileName(Process);
		if (MmIsAddressValid(lpFileName))
		{
			// 
			if (!_stricmp(lpFileName, "YourEACGame.exe") ||
				strstr(lpFileName, "YourEACGame.exe"))
			{
				if (Create)
				{
					pParentId = ParentId;
					pGameId = ProcessId;
					DbgPrint("[EAC_Bypass] Protected process %d found %I64x %I64x", ProcessId, EAC_Base, EAC_Base_Size);
					FilterAddr = 0;
					IsBypassEnabled = FALSE;
					if (Do_Bypass() == FALSE)
						DbgPrint("[EAC_Bypass] WARNING : Do_Bypass failed");
					IsBypassEnabled = TRUE;
#if (RESTORE_ROUTINES == 1)
					if (RestoreThreadCallBack() == FALSE)
						DbgPrint("[EAC_Bypass] WARNING : RestoreImageCallBack failed.");
					if (RestoreImageCallBack() == FALSE)
						DbgPrint("[EAC_Bypass] WARNING : RestoreImageCallBack failed.");

#endif
				}
			}
		}
	}

	VirtualizerStrEncryptEnd();
	VirtualizerEnd();
}


#pragma endregion Routines

BOOLEAN InitBypass()
{
	VirtualizerStart();
	VirtualizerStrEncryptStart();
	BOOLEAN Result = FALSE;
	RTL_OSVERSIONINFOW	osInfo;
	PVOID Base = 0;
	PIMAGE_NT_HEADERS64 Header = 0;
	PIMAGE_SECTION_HEADER pFirstSec = 0;
	ANSI_STRING s1, s2;
	PVOID pFound = 0;
	NTSTATUS status = -1;
	RtlFillMemory(&osInfo, sizeof(RTL_OSVERSIONINFOW), 0);
	RtlFillMemory(&s1, sizeof(ANSI_STRING), 0);
	RtlFillMemory(&s2, sizeof(ANSI_STRING), 0);
	osInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);
	RtlGetVersion(&osInfo);

	DbgPrint("[EAC_Bypass] OsInfo: BuildNumber[%ld] dwMajorVersion[%d] dwMinorVersion[%d]", osInfo.dwBuildNumber, osInfo.dwMajorVersion, osInfo.dwMinorVersion);
	if (6 == osInfo.dwMajorVersion)
	{
		if (osInfo.dwMinorVersion == 1)
		{
			DbgPrint("[EAC_Bypass] Windows 7 detected");
			//Windows 7
			Base = GetKernelBase();
			if (Base == 0)
			{
				DbgPrint("[EAC_Bypass] GetKernelBase failed.");
				return Result;
			}
			Header = RtlImageNtHeader(Base);
			pFirstSec = (PIMAGE_SECTION_HEADER)(Header + 1);
			for (PIMAGE_SECTION_HEADER pSec = pFirstSec; pSec < pFirstSec + (Header->FileHeader.NumberOfSections); pSec++)
			{
				RtlInitAnsiString(&s1, "PAGE");
				RtlInitAnsiString(&s2, (PCCHAR)pSec->Name);
				if (RtlCompareString(&s1, &s2, TRUE) == 0)
				{
					//BE ?? ?? ?? ?? 6A 00 8B CB 8B C6 E8 ?? ?? ?? ??  84 C0 75 20 83 C7 04 83 C6 04 81 ?? ?? ?? ?? ?? 72 E3 53 E8 ?? ?? ?? ??  B8 ?? ?? ?? ??  5F
					UCHAR ImageCallBacks_pattern[] = "\x48\x8D\x0D\xCC\xCC\xCC\xCC\x45\x33\xC0\x48\x8B\xD7\x48\x8D\x0C\xD9\xE8\xCC\xCC\xCC\xCC\x84\xC0\x75\xCC\xFF\xC3\x83\xFB\x08\xCC\xCC\x48\x8B\xCF";
					UCHAR ImageCallBacks_pattern2[] = "\xBE\xCC\xCC\xCC\xCC\x6A\x00\x8B\xCB\x8B\xC6\xE8\xCC\xCC\xCC\xCC\x84\xC0\x75\x20\x83\xC7\x04\x83\xC6\x04\x81\xCC\xCC\xCC\xCC\xCC\x72\xE3\x53\xE8\xCC\xCC\xCC\xCC\xB8\xCC\xCC\xCC\xCC";

					//BE ?? ?? ?? ?? 6A 00 8B CB 8B C6 E8 ?? ?? ?? ??  84 C0 75 20 83 C7 04 83 C6 04 81 ?? ?? ?? ?? ?? 72 E3 53 E8 ?? ?? ?? ??  B8 ?? ?? ?? ??  5E
					UCHAR ThreadCallBacks_pattern[] = "\x48\x8D\x1D\xCC\xCC\xCC\xCC\x41\xBF\x40\x00\x00\x00\x48\x8B\xCB";
					UCHAR ThreadCallBacks_pattern2[] = "\xBE\xCC\xCC\xCC\xCC\x6A\x00\x8B\xCB\x8B\xC\xE8\xCC\xCC\xCC\xCC\x84\xC0\x75\x20\x83\xC7\x04\x83\xC6\x04\x81\xCC\xCC\xCC\xCC\xCC\x72\xE3\x53\xE8\xCC\xCC\xCC\xCC\xB8\xCC\xCC\xCC\xCC\x5E";
					UCHAR PsSuspendThread_pattern[] = "\xE8\xCC\xCC\xCC\xCC\x8B\xF8\x48\x8B\x4C\x24\x68\xE8\xCC\xCC\xCC\xCC\xCC\x48";
					//E8 ?? ?? ?? ?? 53 8B 45 08 E8 ?? ?? ?? ?? 8B D8 85 DB 75 E9
					UCHAR PsSuspendThread_pattern2[] = "\xE8\xCC\xCC\xCC\xCC\x53\x8B\x45\x08\xE8\xCC\xCC\xCC\xCC\x8B\xD8\x85\xDB\x75\xE9";
					// E8 ?? ?? ?? ?? 8B D8 85 DB 75 EA 8B 0F 83 E1 FE
					UCHAR PsResumeThread_pattern[] = "\xE8\xCC\xCC\xCC\xCC\x8B\xF8\x48\x8B\x4C\x24\x60\xE8";
					UCHAR PsResumeThread_pattern2[] = "\xE8\xCC\xCC\xCC\xCC\x8B\xD8\x85\xDB\x75\xEA\x8B\x0F\x83\xE1\xFE";
					status = SearchPattern(ImageCallBacks_pattern, 0xCC, sizeof(ImageCallBacks_pattern) - 1, (void*)((PUCHAR)(Base)+pSec->VirtualAddress), pSec->Misc.VirtualSize, &pFound);
					if (NT_SUCCESS(status))
						ImageCallBacks = (PVOID*)dereference((uintptr_t)pFound, 3);
					if (!ImageCallBacks)
					{
						status = SearchPattern(ImageCallBacks_pattern2, 0xCC, sizeof(ImageCallBacks_pattern2) - 1, (void*)((PUCHAR)(Base)+pSec->VirtualAddress), pSec->Misc.VirtualSize, &pFound);
						if (NT_SUCCESS(status))
						{
							DbgPrint("[EAC_Bypass] ImageCallBacks found!!");
							ImageCallBacks = *(uintptr_t*)((uintptr_t)(pFound)+1);
						}
						if (!ImageCallBacks)
						{
							DbgPrint("[EAC_Bypass] ImageCallBacks not found.");
							return Result;
						}
					}
					
					pFound = 0;
					status = SearchPattern(ThreadCallBacks_pattern, 0xCC, sizeof(ThreadCallBacks_pattern) - 1, (void*)((PUCHAR)(Base)+pSec->VirtualAddress), pSec->Misc.VirtualSize, &pFound);
					if (NT_SUCCESS(status))
						ThreadCallBacks = (PVOID*)dereference((uintptr_t)pFound, 3);
					if (!ThreadCallBacks)
					{
						status = SearchPattern(ThreadCallBacks_pattern2, 0xCC, sizeof(ThreadCallBacks_pattern2) - 1, (void*)((PUCHAR)(Base)+pSec->VirtualAddress), pSec->Misc.VirtualSize, &pFound);
						if (NT_SUCCESS(status))
							ThreadCallBacks = *(uintptr_t*)((uintptr_t)(pFound)+1);
						if (!ThreadCallBacks)
						{
							DbgPrint("[EAC_Bypass] ThreadCallBacks not found.");
							return Result;
						}
					}
					
					pFound = 0;
					status = SearchPattern(PsSuspendThread_pattern, 0xCC, sizeof(PsSuspendThread_pattern) - 1, (void*)((PUCHAR)(Base)+pSec->VirtualAddress), pSec->Misc.VirtualSize, &pFound);
					if (NT_SUCCESS(status))
						o_PsSuspendThread = (p_PsSuspendThread)dereference((uintptr_t)pFound, 1);
					if (!o_PsSuspendThread)
					{
						status = SearchPattern(PsSuspendThread_pattern2, 0xCC, sizeof(PsSuspendThread_pattern2) - 1, (void*)((PUCHAR)(Base)+pSec->VirtualAddress), pSec->Misc.VirtualSize, &pFound);
						if (NT_SUCCESS(status))
							o_PsSuspendThread = (p_PsSuspendThread)dereference((uintptr_t)pFound, 1);
						if (!o_PsSuspendThread)
						{
							DbgPrint("[EAC_Bypass] o_PsSuspendThread not found.");
							return Result;
						}
					}
					pFound = 0;
					status = SearchPattern(PsResumeThread_pattern, 0xCC, sizeof(PsResumeThread_pattern) - 1, (void*)((PUCHAR)(Base)+pSec->VirtualAddress), pSec->Misc.VirtualSize, &pFound);
					if (NT_SUCCESS(status))
						o_PsResumeThread = (p_PsResumeThread)dereference((uintptr_t)pFound, 1);
					if (!o_PsResumeThread)
					{
						status = SearchPattern(PsResumeThread_pattern2, 0xCC, sizeof(PsResumeThread_pattern2) - 1, (void*)((PUCHAR)(Base)+pSec->VirtualAddress), pSec->Misc.VirtualSize, &pFound);
						if (NT_SUCCESS(status))
							o_PsResumeThread = (p_PsResumeThread)dereference((uintptr_t)pFound, 1);
						if (!o_PsResumeThread)
						{
							DbgPrint("[EAC_Bypass] o_PsResumeThread not found.");
							return Result;
						}
					}
				}
			}
			if (ImageCallBacks && ThreadCallBacks && o_PsSuspendThread && o_PsResumeThread)
			{
				DbgPrint("[EAC_Bypass] PsSuspendThread found at 0x%llX", o_PsSuspendThread);
				DbgPrint("[EAC_Bypass] PsResumeThread found at 0x%llX", o_PsResumeThread);
				DbgPrint("[EAC_Bypass] ImageCallBacks found at 0x%llX", ImageCallBacks);
				DbgPrint("[EAC_Bypass] ThreadCallBacks found at 0x%llX", ThreadCallBacks);
				DbgPrint("[EAC_Bypass] All Addresses found. Bypass is ready!");
				Result = 1;
			}
		}
		else if (osInfo.dwMinorVersion == 3)
		{
			// Win8.1
			DbgPrint("[EAC_Bypass] Windows 8.1 detected");
			Base = GetKernelBase();
			if (Base == 0)
			{
				DbgPrint("[EAC_Bypass] GetKernelBase failed.");
				return Result;
			}
			Header = RtlImageNtHeader(Base);
			pFirstSec = (PIMAGE_SECTION_HEADER)(Header + 1);
			for (PIMAGE_SECTION_HEADER pSec = pFirstSec; pSec < pFirstSec + (Header->FileHeader.NumberOfSections); pSec++)
			{
				RtlInitAnsiString(&s1, "PAGE");
				RtlInitAnsiString(&s2, (PCCHAR)pSec->Name);
				if (RtlCompareString(&s1, &s2, TRUE) == 0)
				{
					UCHAR ImageCallBacks_pattern[] = "\x48\x8D\x3D\xCC\xCC\xCC\xCC\xBD\x40\x00\x00\x00\x89\x06";
					UCHAR ThreadCallBacks_pattern[] = "\x48\x8D\x1D\xCC\xCC\xCC\xCC\x41\xBF\x40\x00\x00\x00\x48\x8B\xCB";
					UCHAR PsSuspendThread_pattern[] = "\xE8\xCC\xCC\xCC\xCC\x8B\xF8\xBA\xCC\xCC\xCC\xCC\x48\x8B\x4C\x24\x68";
					UCHAR PsResumeThread_pattern[] = "\xE8\xCC\xCC\xCC\xCC\x8B\xF8\x83\xF8\x01\x75\xCC\x48\x8B\x8E\xCC\xCC\xCC\xCC";
					status = SearchPattern(ImageCallBacks_pattern, 0xCC, sizeof(ImageCallBacks_pattern) - 1, (void*)((PUCHAR)(Base)+pSec->VirtualAddress), pSec->Misc.VirtualSize, &pFound);
					if (NT_SUCCESS(status))
						ImageCallBacks = (PVOID*)dereference((uintptr_t)pFound, 3);
					if (!ImageCallBacks)
					{
						DbgPrint("[EAC_Bypass] ImageCallBacks not found.");
						return Result;
					}
					pFound = 0;
					status = SearchPattern(ThreadCallBacks_pattern, 0xCC, sizeof(ThreadCallBacks_pattern) - 1, (void*)((PUCHAR)(Base)+pSec->VirtualAddress), pSec->Misc.VirtualSize, &pFound);
					if (NT_SUCCESS(status))
						ThreadCallBacks = (PVOID*)dereference((uintptr_t)pFound, 3);
					if (!ThreadCallBacks)
					{
						DbgPrint("[EAC_Bypass] ThreadCallBacks not found.");
						return Result;
					}
					pFound = 0;
					status = SearchPattern(PsSuspendThread_pattern, 0xCC, sizeof(PsSuspendThread_pattern) - 1, (void*)((PUCHAR)(Base)+pSec->VirtualAddress), pSec->Misc.VirtualSize, &pFound);
					if (NT_SUCCESS(status))
						o_PsSuspendThread = (p_PsSuspendThread)dereference((uintptr_t)pFound, 1);
					if (!o_PsSuspendThread)
					{
						DbgPrint("[EAC_Bypass] o_PsSuspendThread not found.");
						return Result;
					}
					pFound = 0;
					status = SearchPattern(PsResumeThread_pattern, 0xCC, sizeof(PsResumeThread_pattern) - 1, (void*)((PUCHAR)(Base)+pSec->VirtualAddress), pSec->Misc.VirtualSize, &pFound);
					if (NT_SUCCESS(status))
						o_PsResumeThread = (p_PsResumeThread)dereference((uintptr_t)pFound, 1);
					if (!o_PsResumeThread)
					{
						DbgPrint("[EAC_Bypass] o_PsResumeThread not found.");
						return Result;
					}
				}
			}
			if (ImageCallBacks && ThreadCallBacks && o_PsSuspendThread && o_PsResumeThread)
			{
				DbgPrint("[EAC_Bypass] PsSuspendThread found at 0x%llX", o_PsSuspendThread);
				DbgPrint("[EAC_Bypass] PsResumeThread found at 0x%llX", o_PsResumeThread);
				DbgPrint("[EAC_Bypass] ImageCallBacks found at 0x%llX", ImageCallBacks);
				DbgPrint("[EAC_Bypass] ThreadCallBacks found at 0x%llX", ThreadCallBacks);
				DbgPrint("[EAC_Bypass] All Addresses found. Bypass is ready!");
				Result = 1;
			}
		}
	}
	else if (osInfo.dwMajorVersion == 10)
	{
		// Win10
		DbgPrint("[EAC_Bypass] Windows 10 detected");
		Base = GetKernelBase();
		if (Base == 0)
		{
			DbgPrint("[EAC_Bypass] GetKernelBase failed.");
			return Result;
		}
		Header = RtlImageNtHeader(Base);
		pFirstSec = (PIMAGE_SECTION_HEADER)(Header + 1);
		for (PIMAGE_SECTION_HEADER pSec = pFirstSec; pSec < pFirstSec + (Header->FileHeader.NumberOfSections); pSec++)
		{
			RtlInitAnsiString(&s1, "PAGE");
			RtlInitAnsiString(&s2, (PCCHAR)pSec->Name);
			if (RtlCompareString(&s1, &s2, TRUE) == 0)
			{
				UCHAR ImageCallBacks_pattern[] = "\x48\x8D\x0D\xCC\xCC\xCC\xCC\x45\x33\xC0\x48\x8D\x0C\xD9\x48\x8B\xD7\xE8\xCC\xCC\xCC\xCC\x84\xC0\x0F\x84\xCC\xCC\xCC\xCC";
				UCHAR ThreadCallBacks_pattern[] = "\x48\x8D\x0D\xCC\xCC\xCC\xCC\x45\x33\xC0\x48\x8D\x0C\xD9\x48\x8B\xD7\xE8\xCC\xCC\xCC\xCC\x84\xC0\x74";
				// for older win10 versions 
				UCHAR ThreadCallBacks2_pattern[] = "\x48\x8D\x0D\xCC\xCC\xCC\xCC\x45\x33\xC0\x48\x8D\x0C\xD9\x48\x8B\xD7\xE8\xCC\xCC\xCC\xCC\x84\xC0\x75";
				UCHAR PsSuspendThread_pattern[] = "\xE8\xCC\xCC\xCC\xCC\x48\x8B\xD6\x48\x8B\xCD\xE8\xCC\xCC\xCC\xCC\x48\x8B\xF0";
				UCHAR PsResumeThread_pattern[] = "\xE8\xCC\xCC\xCC\xCC\x48\x8B\xD7\x48\x8B\xCD\xE8\xCC\xCC\xCC\xCC\xEB\xCC\xBB";
				// old win10 builds
				UCHAR PsSuspendThread3_pattern[] = "\xE8\xCC\xCC\xCC\xCC\x8B\xF8\xBA\xCC\xCC\xCC\xCC\x48\x8B\x4C\x24\x78";
				UCHAR PsResumeThread3_pattern[] = "\xE8\xCC\xCC\xCC\xCC\xBA\xCC\xCC\xCC\xCC\x48\x8B\x4C\x24\x78\xE8\xCC\xCC\xCC\xCC\x90";

				// for win10 ver 1903 and higher
				UCHAR PsSuspendThread2_pattern[] = "\xE8\xCC\xCC\xCC\xCC\x48\x8B\xD7\x48\x8B\xCE\xE8\xCC\xCC\xCC\xCC\x48\x8B\xF8";
				UCHAR PsResumeThread2_pattern[] = "\xE8\xCC\xCC\xCC\xCC\x48\x8B\xD7\x48\x8B\xCE\xE8\xCC\xCC\xCC\xCC\xCC\xCC\x49\x8B\xCE";

				status = SearchPattern(ImageCallBacks_pattern, 0xCC, sizeof(ImageCallBacks_pattern) - 1, (void*)((PUCHAR)(Base)+pSec->VirtualAddress), pSec->Misc.VirtualSize, &pFound);
				if (NT_SUCCESS(status))
					ImageCallBacks = (PVOID*)dereference((uintptr_t)pFound, 3);
				if (!ImageCallBacks)
				{
					DbgPrint("[EAC_Bypass] ImageCallBacks not found.");
					return Result;
				}
				pFound = 0;
				status = SearchPattern(ThreadCallBacks_pattern, 0xCC, sizeof(ThreadCallBacks_pattern) - 1, (void*)((PUCHAR)(Base)+pSec->VirtualAddress), pSec->Misc.VirtualSize, &pFound);
				if (NT_SUCCESS(status))
					ThreadCallBacks = (PVOID*)dereference((uintptr_t)pFound, 3);
				if (!ThreadCallBacks)
				{
					DbgPrint("[EAC_Bypass] ThreadCallBacks not found.Retrying...");
					status = SearchPattern(ThreadCallBacks2_pattern, 0xCC, sizeof(ThreadCallBacks2_pattern) - 1, (void*)((PUCHAR)(Base)+pSec->VirtualAddress), pSec->Misc.VirtualSize, &pFound);
					if (NT_SUCCESS(status))
						ThreadCallBacks = (PVOID*)dereference((uintptr_t)pFound, 3);
					if (!ThreadCallBacks)
					{
						DbgPrint("[EAC_Bypass] ThreadCallBacks not found.");
						return Result;
					}

				}
				pFound = 0;
				status = SearchPattern(PsSuspendThread_pattern, 0xCC, sizeof(PsSuspendThread_pattern) - 1, (void*)((PUCHAR)(Base)+pSec->VirtualAddress), pSec->Misc.VirtualSize, &pFound);
				if (NT_SUCCESS(status))
					o_PsSuspendThread = (p_PsSuspendThread)dereference((uintptr_t)pFound, 1);
				if (!o_PsSuspendThread)
				{
					DbgPrint("[EAC_Bypass] o_PsSuspendThread not found.Retrying...");
					status = SearchPattern(PsSuspendThread2_pattern, 0xCC, sizeof(PsSuspendThread2_pattern) - 1, (void*)((PUCHAR)(Base)+pSec->VirtualAddress), pSec->Misc.VirtualSize, &pFound);
					if (NT_SUCCESS(status))
						o_PsSuspendThread = (p_PsSuspendThread)dereference((uintptr_t)pFound, 1);
					if (!o_PsSuspendThread)
					{
						DbgPrint("[EAC_Bypass] o_PsSuspendThread not found.Retrying...");
						status = SearchPattern(PsSuspendThread3_pattern, 0xCC, sizeof(PsSuspendThread3_pattern) - 1, (void*)((PUCHAR)(Base)+pSec->VirtualAddress), pSec->Misc.VirtualSize, &pFound);
						if (NT_SUCCESS(status))
							o_PsSuspendThread = (p_PsSuspendThread)dereference((uintptr_t)pFound, 1);
						if (!o_PsSuspendThread)
						{
							DbgPrint("[EAC_Bypass] o_PsSuspendThread not found.");
							return Result;
						}
					}
				}
				pFound = 0;
				status = SearchPattern(PsResumeThread_pattern, 0xCC, sizeof(PsResumeThread_pattern) - 1, (void*)((PUCHAR)(Base)+pSec->VirtualAddress), pSec->Misc.VirtualSize, &pFound);
				if (NT_SUCCESS(status))
					o_PsResumeThread = (p_PsResumeThread)dereference((uintptr_t)pFound, 1);
				if (!o_PsResumeThread)
				{
					DbgPrint("[EAC_Bypass] o_PsResumeThread not found.Retrying...");
					status = SearchPattern(PsResumeThread2_pattern, 0xCC, sizeof(PsResumeThread2_pattern) - 1, (void*)((PUCHAR)(Base)+pSec->VirtualAddress), pSec->Misc.VirtualSize, &pFound);
					if (NT_SUCCESS(status))
						o_PsResumeThread = (p_PsResumeThread)dereference((uintptr_t)pFound, 1);
					if (!o_PsResumeThread)
					{
						DbgPrint("[EAC_Bypass] o_PsResumeThread not found.Retrying...");
						status = SearchPattern(PsResumeThread3_pattern, 0xCC, sizeof(PsResumeThread3_pattern) - 1, (void*)((PUCHAR)(Base)+pSec->VirtualAddress), pSec->Misc.VirtualSize, &pFound);
						if (NT_SUCCESS(status))
							o_PsResumeThread = (p_PsResumeThread)dereference((uintptr_t)pFound, 1);
						if (!o_PsResumeThread)
						{
							DbgPrint("[EAC_Bypass] o_PsResumeThread not found.");
							return Result;
						}
					}
				}
			}
		}
		if (ImageCallBacks && ThreadCallBacks && o_PsSuspendThread && o_PsResumeThread)
		{
			DbgPrint("[EAC_Bypass] PsSuspendThread found at 0x%llX", o_PsSuspendThread);
			DbgPrint("[EAC_Bypass] PsResumeThread found at 0x%llX", o_PsResumeThread);
			DbgPrint("[EAC_Bypass] ImageCallBacks found at 0x%llX", ImageCallBacks);
			DbgPrint("[EAC_Bypass] ThreadCallBacks found at 0x%llX", ThreadCallBacks);
			DbgPrint("[EAC_Bypass] All Addresses found. Bypass is ready!");
			Result = 1;
		}
	}

	if (Result == 0)
		return Result;

	if (!NT_SUCCESS(PsSetLoadImageNotifyRoutine(ImageRoutine)) ||
		!NT_SUCCESS(PsSetCreateProcessNotifyRoutine(ProcessRoutine, 0)))
	{
		VirtualizerStrEncryptStart();
		DbgPrint("[EAC_Bypass] CallBack installation failed.");
		VirtualizerStrEncryptEnd();
		Result = 0;
		return Result;
	}
	ProcessPreOperation = 0;
	ProcessPostOperation = 0;
	ThreadPreOperation = 0;
	ThreadPostOperation = 0;
	VirtualizerStrEncryptEnd();
	VirtualizerEnd();
	return Result;
}

BOOLEAN UninitBypass()
{
	VirtualizerStart();
	VirtualizerStrEncryptStart();
	BOOLEAN Result = 1;
	if (ProcessPreOperation || ProcessPostOperation || ThreadPreOperation || ThreadPostOperation)
	{
		if (!Remove_Bypass())
		{
			DbgPrint("[EAC_Bypass] WARNING : Failed to reset the callbacks");
			Result = 0;
		}
	}
	IsBypassEnabled = FALSE;
#if (RESTORE_ROUTINES == 1)
	if (RestoreThreadCallBack() == FALSE)
		DbgPrint("[EAC_Bypass] WARNING : RestoreImageCallBack failed.");
	if (RestoreImageCallBack() == FALSE)
		DbgPrint("[EAC_Bypass] WARNING : RestoreImageCallBack failed.");
#endif
	if (FilterAddr)
	{
		if (!RestoreMiniFilter())
		{
			DbgPrint("[EAC_Bypass] Failed to restore the minifilter");
			Result = 0;
		}
	}
	if (!NT_SUCCESS(PsRemoveLoadImageNotifyRoutine(ImageRoutine)) ||
		!NT_SUCCESS(PsSetCreateProcessNotifyRoutine(ProcessRoutine, 1)))
	{
		DbgPrint("[EAC_Bypass] Failed to remove the callbacks");
		Result = 0;
	}
	VirtualizerStrEncryptEnd();
	VirtualizerEnd();
	return Result;
}

VOID OnUnload(IN PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	VirtualizerStart();
	VirtualizerStrEncryptStart();

	UNICODE_STRING symLink;
	RtlInitUnicodeString(&symLink, dSymLinkBuffer);

	if (!NT_SUCCESS(IoDeleteSymbolicLink(&symLink)))
	{
		DbgPrint("[EAC_Bypass] WARNING : IoDeleteSymbolicLink failed.");
	}
	if (pDeviceObject)
		IoDeleteDevice(pDeviceObject);
	if (!UninitBypass())
		DbgPrint("[EAC_Bypass] WARNING : Failed to uninitialize the bypass.");
	VirtualizerStrEncryptEnd();
	VirtualizerEnd();

}


NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	VirtualizerStart();
	VirtualizerStrEncryptStart();
	NTSTATUS ntStatus = -1;
	UNICODE_STRING deviceNameUnicodeString, deviceSymLinkUnicodeString;

	RtlInitUnicodeString(&deviceNameUnicodeString, dNameBuffer);
	RtlInitUnicodeString(&deviceSymLinkUnicodeString, dSymLinkBuffer);

	DriverObject->DriverUnload = OnUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DeviceCreate;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = DeviceClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceIoHandler;

	if (InitBypass() == 0)
	{
		DbgPrint("[EAC_Bypass] InitBypass failed.");
		return ntStatus;
	}

	ntStatus = IoCreateDevice(DriverObject, 0, &deviceNameUnicodeString, FILE_DEVICE_UNKNOWN, FILE_DEVICE_UNKNOWN, FALSE, &pDeviceObject);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("[EAC_Bypass] IoCreateDevice failed.");
		return ntStatus;
	}
	ntStatus = IoCreateSymbolicLink(&deviceSymLinkUnicodeString, &deviceNameUnicodeString);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("[EAC_Bypass] IoCreateSymbolicLink failed.");
		return ntStatus;
	}
	//HideDriver(DriverObject);
	VirtualizerStrEncryptEnd();
	VirtualizerEnd();
	return ntStatus;
}

NTSTATUS DeviceCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	UNREFERENCED_PARAMETER(Irp);
	return STATUS_SUCCESS;
}

NTSTATUS DeviceClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	UNREFERENCED_PARAMETER(Irp);
	return STATUS_SUCCESS;
}

NTSTATUS DeviceIoHandler(PDEVICE_OBJECT DeviceObject, PIRP IRP)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	VirtualizerStart();
	VirtualizerStrEncryptStart();
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(IRP);
	IRP->IoStatus.Status = STATUS_SUCCESS;
	if (stack)
	{
		if (stack->Parameters.DeviceIoControl.IoControlCode == ctl_protectprocess)
		{
			PHIDEPROC_STRUCT buffer = (PHIDEPROC_STRUCT)IRP->AssociatedIrp.SystemBuffer;
			if (MmIsAddressValid(buffer))
				ProcessIdToProtect = buffer->pId;
			IRP->IoStatus.Information = sizeof(PHIDEPROC_STRUCT);
		}

		if (stack->Parameters.DeviceIoControl.IoControlCode == ctl_isenabled)
		{
			PIS_ENABLED_STRUCT buffer = (PIS_ENABLED_STRUCT)IRP->AssociatedIrp.SystemBuffer;
			if (MmIsAddressValid(buffer))
				buffer->IsEnabled = IsBypassEnabled;
			IRP->IoStatus.Information = sizeof(PIS_ENABLED_STRUCT);
		}
		if (stack->Parameters.DeviceIoControl.IoControlCode == ctl_getprocid)
		{
			PGETPROC_STRUCT buffer = (PGETPROC_STRUCT)IRP->AssociatedIrp.SystemBuffer;
			if (MmIsAddressValid(buffer))
				buffer->pId = pGameId;
			IRP->IoStatus.Information = sizeof(PGETPROC_STRUCT);
		}
	}

	IoCompleteRequest(IRP, IO_NO_INCREMENT);
	VirtualizerStrEncryptEnd();
	VirtualizerEnd();
	return IRP->IoStatus.Status;
}

#pragma region Utils

// Credits to DarthTon (BlackBone, Github)
NTSTATUS SearchPattern(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound)
{
	ASSERT(ppFound != NULL && pattern != NULL && base != NULL);
	if (ppFound == NULL || pattern == NULL || base == NULL)
		return STATUS_INVALID_PARAMETER;

	for (ULONG_PTR i = 0; i < size - len; i++)
	{
		BOOLEAN found = TRUE;
		for (ULONG_PTR j = 0; j < len; j++)
		{
			if (pattern[j] != wildcard && pattern[j] != ((PCUCHAR)base)[i + j])
			{
				found = FALSE;
				break;
			}
		}
		if (found != FALSE)
		{
			*ppFound = (PUCHAR)base + i;
			return STATUS_SUCCESS;
		}
	}
	return STATUS_NOT_FOUND;
}



PVOID GetKernelBase()
{
	VirtualizerStart();
	VirtualizerStrEncryptStart();
	NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;
	PVOID Base = 0;
	ULONG cb = 0x10000;
	do
	{
		status = STATUS_INSUFFICIENT_RESOURCES;
		PRTL_PROCESS_MODULES prpm = (PRTL_PROCESS_MODULES)ExAllocatePool(PagedPool, cb);
		if (prpm)
		{
			if (0 <= (status == ZwQuerySystemInformation(0x0B, prpm, cb, &cb)))
			{
				ULONG NumberOfModules = prpm->NumberOfModules;
				if (NumberOfModules)
				{
					PRTL_PROCESS_MODULE_INFORMATION Modules = prpm->Modules;
					do
					{
						if ((ULONG64)Modules->ImageBase > (ULONG64)(0x8000000000000000))
						{
							Base = Modules->ImageBase;
							break;
						}
					} while (Modules++, --NumberOfModules);
				}
			}
			ExFreePool(prpm);
		}

	} while (status == STATUS_INFO_LENGTH_MISMATCH);
	VirtualizerStrEncryptEnd();
	VirtualizerEnd();
	return Base;
}

BOOLEAN IsFromEACRange(PVOID Address)
{
	if ((ULONG64)Address > (ULONG64)EAC_Base &&
		(ULONG64)((ULONG64)EAC_Base + (ULONG64)EAC_Base_Size) > (ULONG64)Address)
	{
		return 1;
	}
	return 0;
}

BOOLEAN SuspendOrResumeAllThreads(BOOLEAN Suspend)
{
	VirtualizerStart();
	VirtualizerStrEncryptStart();
	ULONG cb = 0x20000;
	PSYSTEM_PROCESS_INFORMATION psi = 0;
	PVOID buf = 0;
	NTSTATUS status = 0, rc = 0;
	PETHREAD peThread = 0;
	do
	{
		status = STATUS_INSUFFICIENT_RESOURCES;

		if (buf = ExAllocatePool(PagedPool, cb))
		{
			if (0 <= (status = ZwQuerySystemInformation(5, buf, cb, &cb)))
			{
				psi = (PSYSTEM_PROCESS_INFORMATION)buf;
				while (psi->NextEntryOffset)
				{
					if (psi->UniqueProcessId == (HANDLE)4)
					{
						for (ULONG i = 0; i < psi->NumberOfThreads; i++)
						{
							if (MmIsAddressValid(psi->Threads[i].StartAddress) && IsFromEACRange(psi->Threads[i].StartAddress))
							{
								rc = PsLookupThreadByThreadId(psi->Threads[i].ClientId.UniqueThread, &peThread);
								if (!NT_SUCCESS(rc))
								{
									DbgPrint("[EAC_Bypass] PsLookupThreadByThreadId failed in SuspendOrResumeAllThreads");
									if (buf)
										ExFreePool(buf);
									return 0;
								}
								if (NT_SUCCESS(rc))
								{
									DbgPrint("[EAC_Bypass] Found EAC Thread %d !", psi->Threads[i].ClientId.UniqueThread);
									if (peThread)
									{
										if (Suspend == TRUE)
										{
											if (!NT_SUCCESS(o_PsSuspendThread(peThread, 0)))
												DbgPrint("[EAC_Bypass] o_PsSuspendThread failed.");
										}
										else
											if (!NT_SUCCESS(o_PsResumeThread(peThread)))
												DbgPrint("[EAC_Bypass] o_PsSuspendThread failed.");
									}
								}
							}
						}

					}
					psi = (PSYSTEM_PROCESS_INFORMATION)((ULONG64)(psi)+psi->NextEntryOffset);
				}

			}
			if (buf)
				ExFreePool(buf);
		}

	} while (status == STATUS_INFO_LENGTH_MISMATCH);
	VirtualizerStrEncryptEnd();
	VirtualizerEnd();
	return (status == 0) ? 1 : 0;
}

// Credits to GayPig (Github), yes I am lazy
uintptr_t dereference(uintptr_t address, unsigned int offset)
{
	if (address == 0)
		return 0;

	return address + (int)((*(int*)(address + offset) + offset) + sizeof(int));
}

#pragma endregion Utils
