#include "EventList.h"
#include "PendingQueue.h"

KPAM_EVENT_LIST g_EventList;

static BOOLEAN CompleteEventIrp(PIRP Irp, PKPAM_EVENT_DATA EventData)
{
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    PKPAM_EVENT_DATA systemBuffer =
        static_cast<PKPAM_EVENT_DATA>(Irp->AssociatedIrp.SystemBuffer);

    if (systemBuffer == nullptr ||
        irpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(KPAM_EVENT_DATA))
    {
        Irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return FALSE;
    }

    *systemBuffer = *EventData;
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = sizeof(KPAM_EVENT_DATA);
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return TRUE;
}

VOID InitializeEventList(VOID)
{
    InitializeListHead(&g_EventList.ListHead);
    KeInitializeSpinLock(&g_EventList.ListLock);
    g_EventList.EventCount = 0;
    g_EventList.DroppedEventCount = 0;
}

VOID KpamInitializeEvent(PKPAM_EVENT_DATA EventData, KPAM_EVENT_TYPE Type, ULONG ProcessId)
{
    RtlZeroMemory(EventData, sizeof(*EventData));
    EventData->Size = sizeof(*EventData);
    EventData->Type = Type;
    EventData->ProcessId = ProcessId;
    KeQuerySystemTime(&EventData->Timestamp);
}

VOID KpamSetEventText(PKPAM_EVENT_DATA EventData, PCUNICODE_STRING Text)
{
    if (Text == nullptr || Text->Buffer == nullptr || Text->Length == 0)
    {
        return;
    }

    ULONG characterCount = Text->Length / sizeof(WCHAR);
    if (characterCount >= KPAM_MAX_EVENT_TEXT_CHARS)
    {
        characterCount = KPAM_MAX_EVENT_TEXT_CHARS - 1;
    }

    RtlCopyMemory(EventData->Text, Text->Buffer, characterCount * sizeof(WCHAR));
    EventData->Text[characterCount] = L'\0';
    EventData->TextLength = characterCount;
}

BOOLEAN GetNextEventFromList(PKPAM_EVENT_DATA OutEventData)
{
    if (OutEventData == nullptr)
    {
        return FALSE;
    }

    KIRQL oldIrql;
    PKPAM_EVENT_LIST_ENTRY entry = nullptr;

    KeAcquireSpinLock(&g_EventList.ListLock, &oldIrql);
    if (!IsListEmpty(&g_EventList.ListHead))
    {
        PLIST_ENTRY link = RemoveHeadList(&g_EventList.ListHead);
        entry = CONTAINING_RECORD(link, KPAM_EVENT_LIST_ENTRY, ListEntry);
        --g_EventList.EventCount;
    }
    KeReleaseSpinLock(&g_EventList.ListLock, oldIrql);

    if (entry == nullptr)
    {
        return FALSE;
    }

    *OutEventData = entry->EventData;
    ExFreePoolWithTag(entry, 'mapK');
    return TRUE;
}

BOOLEAN IsEventListEmpty(VOID)
{
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_EventList.ListLock, &oldIrql);
    BOOLEAN isEmpty = IsListEmpty(&g_EventList.ListHead);
    KeReleaseSpinLock(&g_EventList.ListLock, oldIrql);
    return isEmpty;
}

VOID KpamTryCompletePendingEvent(VOID)
{
    for (;;)
    {
        if (IsEventListEmpty())
        {
            return;
        }

        PIRP pendingIrp = IoCsqRemoveNextIrp(&g_Csq, nullptr);
        if (pendingIrp == nullptr)
        {
            return;
        }

        KPAM_EVENT_DATA eventData;
        if (GetNextEventFromList(&eventData))
        {
            CompleteEventIrp(pendingIrp, &eventData);
            continue;
        }

        IoCsqInsertIrp(&g_Csq, pendingIrp, nullptr);
    }
}

BOOLEAN AddEventToList(PKPAM_EVENT_DATA EventData)
{
    if (EventData == nullptr)
    {
        return FALSE;
    }

    PIRP pendingIrp = IoCsqRemoveNextIrp(&g_Csq, nullptr);
    if (pendingIrp != nullptr)
    {
        return CompleteEventIrp(pendingIrp, EventData);
    }

    PKPAM_EVENT_LIST_ENTRY newEntry =
        static_cast<PKPAM_EVENT_LIST_ENTRY>(ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            sizeof(KPAM_EVENT_LIST_ENTRY),
            'mapK'));

    if (newEntry == nullptr)
    {
        DbgPrint("[KPAM] Failed to allocate memory for new event entry.\n");
        return FALSE;
    }

    newEntry->EventData = *EventData;

    BOOLEAN queued = FALSE;
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_EventList.ListLock, &oldIrql);
    if (g_EventList.EventCount < KPAM_MAX_QUEUED_EVENTS)
    {
        InsertTailList(&g_EventList.ListHead, &newEntry->ListEntry);
        ++g_EventList.EventCount;
        queued = TRUE;
    }
    else
    {
        ++g_EventList.DroppedEventCount;
    }
    KeReleaseSpinLock(&g_EventList.ListLock, oldIrql);

    if (!queued)
    {
        ExFreePoolWithTag(newEntry, 'mapK');
        return FALSE;
    }

    KpamTryCompletePendingEvent();
    return TRUE;
}

VOID KpamCancelPendingEvents(VOID)
{
    PIRP pendingIrp;
    while ((pendingIrp = IoCsqRemoveNextIrp(&g_Csq, nullptr)) != nullptr)
    {
        pendingIrp->IoStatus.Status = STATUS_CANCELLED;
        pendingIrp->IoStatus.Information = 0;
        IoCompleteRequest(pendingIrp, IO_NO_INCREMENT);
    }
}

VOID ClearEventList(VOID)
{
    KPAM_EVENT_DATA ignoredEvent;
    while (GetNextEventFromList(&ignoredEvent))
    {
    }

    DbgPrint("[KPAM] Event list cleared, memory freed. Dropped events: %lu\n",
        g_EventList.DroppedEventCount);
}
