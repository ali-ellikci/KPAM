#include "RegistryLogic.h"
#include "ProcessLogic.h"
#include "EventList.h"

LARGE_INTEGER g_RegCookie;

NTSTATUS KpamRegistryCallback(
    PVOID CallbackContext,
    PVOID Argument1,
    PVOID Argument2
)
{
    UNREFERENCED_PARAMETER(CallbackContext);
    UNREFERENCED_PARAMETER(Argument2);

    
    HANDLE processId = PsGetCurrentProcessId();
    ULONG pid = HandleToUlong(processId);

    
    if (KpamIsProcessMonitored(pid))
    {
        REG_NOTIFY_CLASS actualNotifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
        switch (actualNotifyClass) {
        case RegNtPreSetValueKey: {
            PREG_SET_VALUE_KEY_INFORMATION info = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;
            if (info && info->ValueName) {
                DbgPrint("[KPAM-REG] Monitored process (PID: %lu) is writing registry value: %wZ\n",
                    pid, info->ValueName);

                KPAM_EVENT_DATA eventData;
                KpamInitializeEvent(&eventData, KpamEventRegistry, pid);
                eventData.Data.RegistryEvent.KeyHandle =
                    reinterpret_cast<ULONGLONG>(info->Object);
                eventData.Data.RegistryEvent.Action = KpamActionRegistrySetValue;
                KpamSetEventText(&eventData, info->ValueName);
                AddEventToList(&eventData);
            }
            break;
        }

        case RegNtPreCreateKeyEx: {
            PREG_CREATE_KEY_INFORMATION info = (PREG_CREATE_KEY_INFORMATION)Argument2;
            if (info && info->CompleteName) {
                DbgPrint("[KPAM-REG] Monitored process (PID: %lu) is creating a new key: %wZ\n",
                    pid, info->CompleteName);

                KPAM_EVENT_DATA eventData;
                KpamInitializeEvent(&eventData, KpamEventRegistry, pid);
                eventData.Data.RegistryEvent.KeyHandle =
                    reinterpret_cast<ULONGLONG>(info->RootObject);
                eventData.Data.RegistryEvent.Action = KpamActionRegistryCreateKey;
                KpamSetEventText(&eventData, info->CompleteName);
                AddEventToList(&eventData);
            }
            break;
        }

        default:
            break;
        }
    }

    return STATUS_SUCCESS;
}
