#define USE_VM 0

#if(USE_VM == 1)
#include "WL\WinlicenseSDK.h"
#if _WIN64
#pragma comment(lib,"WinLicenseSDK64.lib")
#else
#pragma comment(lib,"WinLicenseSDK32.lib")
#endif
#else
#define VM_START
#define VM_END
#endif
