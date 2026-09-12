#pragma once

extern "C" {
#include <fltkernel.h>
}

extern PFLT_FILTER g_MinifilterHandle;

NTSTATUS KpamRegisterMinifilter(PDRIVER_OBJECT DriverObject);

void KpamUnregisterMinifilter();
