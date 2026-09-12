#pragma once
#include "KpamData.h"

extern PVOID g_ObRegistrationHandle;

OB_PREOP_CALLBACK_STATUS KpamPreOpenProcessOrThread(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation
);

NTSTATUS KpamRegisterObCallbacks(PDRIVER_OBJECT DriverObject);
void KpamUnregisterObCallbacks();
