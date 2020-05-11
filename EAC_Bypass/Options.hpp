#pragma once


#define REMOVE_IMAGEROUTINE 1
#define REMOVE_THREADROUTINE 1
#define REMOVE_PROCESSCALLBACKS 1
#define REMOVE_THREADCALLBACKS 1
#define REMOVE_FILTER 0
#define SUSPEND_EAC 1
#define PROTECT_PROCESS 1
#define RESTORE_ROUTINES 1
#define USE_VM 0

#if(USE_VM == 1)
#include "VL\VirtualizerSDK.h"
#else
#define VM_TIGER_WHITE_START
#define VM_TIGER_WHITE_END
#define VM_TIGER_WHITE_START
#define VM_TIGER_WHITE_END
#define VM_EAGLE_BLACK_START
#define VM_EAGLE_BLACK_END
#define VIRTUALIZER_TIGER_WHITE_START 
#define VIRTUALIZER_TIGER_WHITE_END 
static void VirtualizerStart() {}
static void VirtualizerEnd() {}
static void VirtualizerStrEncryptStart() {}
static void VirtualizerStrEncryptEnd() {}
#endif