#pragma once
#include <ntddk.h>
#include "Shared.h"

typedef struct _FOLLOWED_PROCESS {
	ULONG ProcessId;
	LIST_ENTRY ListEntry;
} FOLLOWED_PROCESS, * PFOLLOWED_PROCESS;

typedef struct _KPAM_GLOBAL_CONTEXT {

	LIST_ENTRY ProcessListHead;
	FAST_MUTEX ProcessListMutex;

	PDEVICE_OBJECT DeviceObject;
} KPAM_GLOBAL_CONTEXT, * PKPAM_GLOBAL_CONTEXT;

extern KPAM_GLOBAL_CONTEXT g_KpamContext;
