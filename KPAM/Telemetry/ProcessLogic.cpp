#include "ProcessLogic.h"
#include "EventList.h"

void InitializeKpamContext() {
	InitializeListHead(&g_KpamContext.ProcessListHead);
	ExInitializeFastMutex(&g_KpamContext.ProcessListMutex);
	g_KpamContext.DeviceObject = nullptr;
}

NTSTATUS KpamAddProcess(ULONG ProcessId) {
	PLIST_ENTRY link;
	BOOLEAN isDuplicate = FALSE;

	ExAcquireFastMutex(&g_KpamContext.ProcessListMutex);

	for (link = g_KpamContext.ProcessListHead.Flink;
		link != &g_KpamContext.ProcessListHead;
		link = link->Flink) {

		PFOLLOWED_PROCESS entry = CONTAINING_RECORD(link, FOLLOWED_PROCESS, ListEntry);
		if (entry->ProcessId == ProcessId) {
			isDuplicate = TRUE;
			break;
		}
	}

	if (isDuplicate) {
		ExReleaseFastMutex(&g_KpamContext.ProcessListMutex);
		DbgPrint("[KPAM] PID %lu is already in the list.\n", ProcessId);
		return STATUS_OBJECT_NAME_EXISTS;
	}

	PFOLLOWED_PROCESS newEntry = (PFOLLOWED_PROCESS)ExAllocatePool2(
		POOL_FLAG_NON_PAGED,
		sizeof(FOLLOWED_PROCESS),
		'mapK'
	);

	if (newEntry == NULL) {
		ExReleaseFastMutex(&g_KpamContext.ProcessListMutex);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	newEntry->ProcessId = ProcessId;
	InsertTailList(&g_KpamContext.ProcessListHead, &newEntry->ListEntry);
	ExReleaseFastMutex(&g_KpamContext.ProcessListMutex);

	DbgPrint("[KPAM] PID %lu is added to the list.\n", ProcessId);
	return STATUS_SUCCESS;
}

BOOLEAN KpamIsProcessMonitored(ULONG ProcessId) {
	BOOLEAN found = FALSE;
	PLIST_ENTRY link;

	ExAcquireFastMutex(&g_KpamContext.ProcessListMutex);

	for (link = g_KpamContext.ProcessListHead.Flink;
		link != &g_KpamContext.ProcessListHead;
		link = link->Flink) {

		PFOLLOWED_PROCESS entry = CONTAINING_RECORD(link, FOLLOWED_PROCESS, ListEntry);
		if (entry->ProcessId == ProcessId) {
			found = TRUE;
			break;
		}
	}

	ExReleaseFastMutex(&g_KpamContext.ProcessListMutex);
	return found;
}

void KpamClearProcessList() {
	ExAcquireFastMutex(&g_KpamContext.ProcessListMutex);

	while (!IsListEmpty(&g_KpamContext.ProcessListHead)) {
		PLIST_ENTRY link = RemoveHeadList(&g_KpamContext.ProcessListHead);
		PFOLLOWED_PROCESS entry = CONTAINING_RECORD(link, FOLLOWED_PROCESS, ListEntry);
		ExFreePoolWithTag(entry, 'mapK');
	}

	ExReleaseFastMutex(&g_KpamContext.ProcessListMutex);
	DbgPrint("[KPAM] List is cleared, memory is freed.\n");
}

extern "C" void KpamCreateProcessNotifyRoutineEx(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
	UNREFERENCED_PARAMETER(Process);

	if (CreateInfo != NULL)
	{

		ULONG parentPid = HandleToUlong(CreateInfo->ParentProcessId);
		ULONG newPid = HandleToUlong(ProcessId);

		if (KpamIsProcessMonitored(parentPid))
		{
			DbgPrint("[KPAM-ALERT] Monitored PID %lu -> New PID: %lu | Path: %wZ\n",
				parentPid, newPid, CreateInfo->ImageFileName);

			KPAM_EVENT_DATA eventData;
			KpamInitializeEvent(&eventData, KpamEventProcess, parentPid);
			eventData.Data.ProcessEvent.RelatedProcessId = newPid;
			eventData.Data.ProcessEvent.Action = KpamActionCreate;
			KpamSetEventText(&eventData, CreateInfo->ImageFileName);
			AddEventToList(&eventData);

			KpamAddProcess(newPid);
		}
	}
	else
	{

		ULONG deadPid = HandleToUlong(ProcessId);

		if (KpamIsProcessMonitored(deadPid))
		{
			DbgPrint("[KPAM] Monitored PID %lu is terminating\n", deadPid);

			KPAM_EVENT_DATA eventData;
			KpamInitializeEvent(&eventData, KpamEventProcess, deadPid);
			eventData.Data.ProcessEvent.Action = KpamActionTerminate;
			AddEventToList(&eventData);

			ExAcquireFastMutex(&g_KpamContext.ProcessListMutex);
			PLIST_ENTRY link;
			for (link = g_KpamContext.ProcessListHead.Flink; link != &g_KpamContext.ProcessListHead; link = link->Flink)
			{
				PFOLLOWED_PROCESS entry = CONTAINING_RECORD(link, FOLLOWED_PROCESS, ListEntry);
				if (entry->ProcessId == deadPid)
				{
					RemoveEntryList(link);
					ExFreePoolWithTag(entry, 'mapK');
					break;
				}
			}
			ExReleaseFastMutex(&g_KpamContext.ProcessListMutex);
		}
	}
}
