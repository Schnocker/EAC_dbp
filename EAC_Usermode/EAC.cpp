#include "EAC.hpp"
#include <TlHelp32.h>

HANDLE EAC::hEvent;
typedef BOOL(NTAPI* p_DeviceIoControl)(HANDLE hDevice, DWORD dwIoControlCode, LPVOID lpInBuffer, DWORD nInBufferSize, LPVOID lpOutBuffer, DWORD nOutBufferSize, LPDWORD lpBytesReturned, LPOVERLAPPED lpOverlapped);
static p_DeviceIoControl o_DeviceIoControl = nullptr;

bool EAC::Init()
{
	return Bypass_DeviceIoControl(true);
}
bool EAC::Uninit()
{
	return Bypass_DeviceIoControl(false);
}


bool WINAPI DeviceIoControl_Hook (HANDLE hDevice, DWORD dwIoControlCode, LPVOID lpInBuffer, DWORD nInBufferSize, LPVOID lpOutBuffer, DWORD nOutBufferSize, LPDWORD lpBytesReturned, LPOVERLAPPED lpOverlapped)
{
	VM_START
	DWORD_PTR dwStartAddress = 0;
	HMODULE hModule = 0;
	static HANDLE hThread = nullptr;
	if (NT_SUCCESS(NtQueryInformationThread(GetCurrentThread(), static_cast<THREADINFOCLASS>(9), &dwStartAddress, sizeof(DWORD_PTR), NULL)) &&
		!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<char*>(dwStartAddress), &hModule))
	{
		if (!EnumWindows([](HWND hWnd, LPARAM lParam) -> BOOL
			{
				DWORD procId = 0;
				if (GetWindowThreadProcessId(hWnd, &procId) && procId == GetCurrentProcessId())
					SuspendThread(GetCurrentThread());
				return TRUE;
			}, NULL))
		{
			MessageBoxExA(0, "Failed to use EnumWindows!", "ERRROR!", 0, 0);
			return false;
		}
	}
	VM_END
	return o_DeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesReturned, lpOverlapped);
};

bool EAC::Bypass_DeviceIoControl(bool detourStatus)
{
	VM_START
	if(!o_DeviceIoControl)
		o_DeviceIoControl = reinterpret_cast<p_DeviceIoControl>(GetProcAddress(GetModuleHandleA("KERNELBASE"), "DeviceIoControl"));
	if (DetourTransactionBegin() != NO_ERROR ||
		DetourUpdateThread(GetCurrentThread()) != NO_ERROR ||
		DetourAttach(&(PVOID&)o_DeviceIoControl, DeviceIoControl_Hook) != NO_ERROR ||
		DetourTransactionCommit() != NO_ERROR)
	{
#if _DEBUG == 1
		std::cout << "Could not hook functions" << std::endl;
#endif
		MessageBoxExA(0, "Failed to hook functions!", "ERRROR!", 0, 0);
		return false;
	}
	VM_END
	return true;
	}