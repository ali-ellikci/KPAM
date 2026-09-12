

#include "FileLogic.h"
#include "ProcessLogic.h"
#include "EventList.h"

PFLT_FILTER g_MinifilterHandle = NULL;

extern "C" {
    FLT_PREOP_CALLBACK_STATUS FLTAPI KpamPreOperationCreate(
        _Inout_     PFLT_CALLBACK_DATA                      Data,
        _In_        PCFLT_RELATED_OBJECTS                   FltObjects,
        _Flt_CompletionContext_Outptr_ PVOID*               CompletionContext
    );

    NTSTATUS FLTAPI KpamFilterUnloadCallback(
        _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

    NTSTATUS FLTAPI KpamInstanceSetupCallback(
        _In_ PCFLT_RELATED_OBJECTS      FltObjects,
        _In_ FLT_INSTANCE_SETUP_FLAGS   Flags,
        _In_ DEVICE_TYPE                VolumeDeviceType,
        _In_ FLT_FILESYSTEM_TYPE        VolumeFilesystemType
    );

    NTSTATUS FLTAPI KpamInstanceQueryTeardownCallback(
        _In_ PCFLT_RELATED_OBJECTS              FltObjects,
        _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS  Flags
    );
}

static CONST FLT_OPERATION_REGISTRATION g_FileCallbacks[] =
{
    {
        IRP_MJ_CREATE,
        0,
        KpamPreOperationCreate,
        NULL
    },
    { IRP_MJ_OPERATION_END }
};

static CONST FLT_REGISTRATION g_FileFilterRegistration =
{
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    g_FileCallbacks,
    KpamFilterUnloadCallback,
    KpamInstanceSetupCallback,
    KpamInstanceQueryTeardownCallback,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

extern "C" {

    FLT_PREOP_CALLBACK_STATUS FLTAPI KpamPreOperationCreate(
        _Inout_     PFLT_CALLBACK_DATA      Data,
        _In_        PCFLT_RELATED_OBJECTS   FltObjects,
        _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
    )
    {
        UNREFERENCED_PARAMETER(FltObjects);
        UNREFERENCED_PARAMETER(CompletionContext);

        ULONG pid = HandleToUlong(PsGetCurrentProcessId());

        if (!KpamIsProcessMonitored(pid))
        {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        if (Data == NULL || Data->Iopb == NULL ||
            Data->Iopb->TargetFileObject == NULL ||
            Data->Iopb->TargetFileObject->FileName.Buffer == NULL)
        {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        DbgPrint("[KPAM-FILE] PID %lu opened file: %wZ\n",
            pid,
            &Data->Iopb->TargetFileObject->FileName);

        KPAM_EVENT_DATA eventData;
        KpamInitializeEvent(&eventData, KpamEventFile, pid);
        KpamSetEventText(&eventData, &Data->Iopb->TargetFileObject->FileName);
        AddEventToList(&eventData);

        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    NTSTATUS FLTAPI KpamFilterUnloadCallback(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
    {
        UNREFERENCED_PARAMETER(Flags);

        return STATUS_SUCCESS;
    }

    NTSTATUS FLTAPI KpamInstanceSetupCallback(
        _In_ PCFLT_RELATED_OBJECTS      FltObjects,
        _In_ FLT_INSTANCE_SETUP_FLAGS   Flags,
        _In_ DEVICE_TYPE                VolumeDeviceType,
        _In_ FLT_FILESYSTEM_TYPE        VolumeFilesystemType
    )
    {
        UNREFERENCED_PARAMETER(FltObjects);
        UNREFERENCED_PARAMETER(Flags);
        UNREFERENCED_PARAMETER(VolumeDeviceType);
        UNREFERENCED_PARAMETER(VolumeFilesystemType);
        return STATUS_SUCCESS;
    }

    NTSTATUS FLTAPI KpamInstanceQueryTeardownCallback(
        _In_ PCFLT_RELATED_OBJECTS              FltObjects,
        _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS  Flags
    )
    {
        UNREFERENCED_PARAMETER(FltObjects);
        UNREFERENCED_PARAMETER(Flags);
        return STATUS_SUCCESS;
    }

}

NTSTATUS KpamRegisterMinifilter(PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status = FltRegisterFilter(
        DriverObject,
        &g_FileFilterRegistration,
        &g_MinifilterHandle
    );

    if (!NT_SUCCESS(status))
    {
        DbgPrint("[KPAM] FltRegisterFilter failed: 0x%X\n", status);
        return status;
    }

    status = FltStartFiltering(g_MinifilterHandle);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[KPAM] FltStartFiltering failed: 0x%X\n", status);
        FltUnregisterFilter(g_MinifilterHandle);
        g_MinifilterHandle = NULL;
        return status;
    }

    DbgPrint("[KPAM] Minifilter registered and filtering started successfully.\n");
    return STATUS_SUCCESS;
}

void KpamUnregisterMinifilter()
{
    if (g_MinifilterHandle != NULL)
    {
        FltUnregisterFilter(g_MinifilterHandle);
        g_MinifilterHandle = NULL;
        DbgPrint("[KPAM] Minifilter unregistered.\n");
    }
}
