#include "EAC.hpp"

__declspec(dllexport) BOOL UNKNOWN(HMODULE hDll, DWORD dwReason, LPVOID lpReserved)
{
	VM_START
	if (dwReason == DLL_PROCESS_ATTACH)
		EAC::GetInstance().Init();
	if (dwReason == DLL_PROCESS_DETACH)
		EAC::GetInstance().Uninit();
	VM_END
	return true;
}