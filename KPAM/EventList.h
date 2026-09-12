#pragma once

#include <ntddk.h>
#include "Shared.h"

#define KPAM_MAX_QUEUED_EVENTS 1024

typedef struct _KPAM_EVENT_LIST {
    LIST_ENTRY ListHead;
    KSPIN_LOCK ListLock;
    ULONG EventCount;
    ULONG DroppedEventCount;
} KPAM_EVENT_LIST, *PKPAM_EVENT_LIST;

typedef struct _KPAM_EVENT_LIST_ENTRY {
    LIST_ENTRY ListEntry;
    KPAM_EVENT_DATA EventData;
} KPAM_EVENT_LIST_ENTRY, *PKPAM_EVENT_LIST_ENTRY;

extern KPAM_EVENT_LIST g_EventList;

VOID InitializeEventList(VOID);
VOID KpamInitializeEvent(PKPAM_EVENT_DATA EventData, KPAM_EVENT_TYPE Type, ULONG ProcessId);
VOID KpamSetEventText(PKPAM_EVENT_DATA EventData, PCUNICODE_STRING Text);
BOOLEAN AddEventToList(PKPAM_EVENT_DATA EventData);
BOOLEAN GetNextEventFromList(PKPAM_EVENT_DATA OutEventData);
BOOLEAN IsEventListEmpty(VOID);
VOID KpamTryCompletePendingEvent(VOID);
VOID KpamCancelPendingEvents(VOID);
VOID ClearEventList(VOID);
