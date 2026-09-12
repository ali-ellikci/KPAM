#pragma once
#include "KpamData.h"

void InitializeKpamContext();
NTSTATUS KpamAddProcess(ULONG ProcessId);
void KpamClearProcessList();
BOOLEAN KpamIsProcessMonitored(ULONG ProcessId);

extern "C" void KpamCreateProcessNotifyRoutineEx(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo);
