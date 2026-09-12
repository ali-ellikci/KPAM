#include "ThreadLogic.h"
#include "ProcessLogic.h"
#include "EventList.h"

void KpamCreateThreadNotifyRoutine(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create)
{
	ULONG pid = HandleToUlong(ProcessId);
	ULONG tid = HandleToUlong(ThreadId);

	if (Create)
	{
		
		if (KpamIsProcessMonitored(pid))
		{
			DbgPrint("[KPAM-ALERT] Thread Created in Monitored Process! PID: %lu -> TID: %lu\n", pid, tid);

			KPAM_EVENT_DATA eventData;
			KpamInitializeEvent(&eventData, KpamEventThread, pid);
			eventData.Data.ThreadEvent.ThreadId = tid;
			eventData.Data.ThreadEvent.Action = KpamActionCreate;
			AddEventToList(&eventData);
		}
	}
	else
	{
		
		if (KpamIsProcessMonitored(pid))
		{
			DbgPrint("[KPAM] Thread Terminated in Monitored Process! PID: %lu -> TID: %lu\n", pid, tid);

			KPAM_EVENT_DATA eventData;
			KpamInitializeEvent(&eventData, KpamEventThread, pid);
			eventData.Data.ThreadEvent.ThreadId = tid;
			eventData.Data.ThreadEvent.Action = KpamActionTerminate;
			AddEventToList(&eventData);
		}
	}
}
