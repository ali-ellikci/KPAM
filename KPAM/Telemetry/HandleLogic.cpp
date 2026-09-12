#include "HandleLogic.h"
#include "ProcessLogic.h"
#include "EventList.h"

PVOID g_ObRegistrationHandle = nullptr;

OB_PREOP_CALLBACK_STATUS KpamPreOpenProcessOrThread(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation
)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    HANDLE currentPid = PsGetCurrentProcessId();
    ULONG callingPid = HandleToUlong(currentPid);

    if (KpamIsProcessMonitored(callingPid))
    {
        ACCESS_MASK desiredAccess =
            OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE
            ? OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess
            : OperationInformation->Parameters->DuplicateHandleInformation.OriginalDesiredAccess;

        KPAM_EVENT_DATA eventData;
        KpamInitializeEvent(&eventData, KpamEventHandle, callingPid);
        eventData.Data.HandleEvent.DesiredAccess = desiredAccess;

        if (OperationInformation->ObjectType == *PsProcessType)
        {
            PEPROCESS targetProcess = (PEPROCESS)OperationInformation->Object;
            HANDLE targetPid = PsGetProcessId(targetProcess);

            DbgPrint("[KPAM-HANDLE-ALERT] Monitored PID %lu requested process handle to PID %lu (DesiredAccess: 0x%X)\n",
                callingPid, HandleToUlong(targetPid), desiredAccess);

            eventData.Data.HandleEvent.ObjectKind = KpamActionProcessHandle;
            eventData.Data.HandleEvent.TargetProcessId = HandleToUlong(targetPid);
            AddEventToList(&eventData);
        }
        else if (OperationInformation->ObjectType == *PsThreadType)
        {
            PETHREAD targetThread = (PETHREAD)OperationInformation->Object;
            HANDLE targetTid = PsGetThreadId(targetThread);
            HANDLE ownerPid = PsGetThreadProcessId(targetThread);

            DbgPrint("[KPAM-HANDLE-ALERT] Monitored PID %lu requested thread handle to TID %lu (Owner PID %lu) (DesiredAccess: 0x%X)\n",
                callingPid, HandleToUlong(targetTid), HandleToUlong(ownerPid), desiredAccess);

            eventData.Data.HandleEvent.ObjectKind = KpamActionThreadHandle;
            eventData.Data.HandleEvent.TargetThreadId = HandleToUlong(targetTid);
            eventData.Data.HandleEvent.OwnerProcessId = HandleToUlong(ownerPid);
            AddEventToList(&eventData);
        }
    }

    return OB_PREOP_SUCCESS;
}

NTSTATUS KpamRegisterObCallbacks(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    OB_CALLBACK_REGISTRATION callbackRegistration;
    OB_OPERATION_REGISTRATION operationRegistration[2];

    operationRegistration[0].ObjectType = PsProcessType;
    operationRegistration[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operationRegistration[0].PreOperation = KpamPreOpenProcessOrThread;
    operationRegistration[0].PostOperation = nullptr;

    operationRegistration[1].ObjectType = PsThreadType;
    operationRegistration[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operationRegistration[1].PreOperation = KpamPreOpenProcessOrThread;
    operationRegistration[1].PostOperation = nullptr;

    callbackRegistration.Version = OB_FLT_REGISTRATION_VERSION;
    callbackRegistration.OperationRegistrationCount = 2;
    RtlInitUnicodeString(&callbackRegistration.Altitude, L"320000");
    callbackRegistration.RegistrationContext = nullptr;
    callbackRegistration.OperationRegistration = operationRegistration;

    return ObRegisterCallbacks(&callbackRegistration, &g_ObRegistrationHandle);
}

void KpamUnregisterObCallbacks()
{
    if (g_ObRegistrationHandle != nullptr)
    {

		ObUnRegisterCallbacks(g_ObRegistrationHandle);
        g_ObRegistrationHandle = nullptr;
    }
}
