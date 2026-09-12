#include "ImageLogic.h"
#include "ProcessLogic.h"
#include "EventList.h"

void KpamLoadImageNotifyRoutine(
    PUNICODE_STRING FullImageName,
    HANDLE ProcessId,
    PIMAGE_INFO ImageInfo
)
{
    UNREFERENCED_PARAMETER(ImageInfo);

    ULONG pid = HandleToUlong(ProcessId);

    if (KpamIsProcessMonitored(pid))
    {
        KPAM_EVENT_DATA eventData;
        KpamInitializeEvent(&eventData, KpamEventImage, pid);
        eventData.Data.ImageEvent.ImageBaseAddress =
            ImageInfo ? reinterpret_cast<ULONGLONG>(ImageInfo->ImageBase) : 0;

        if (FullImageName != NULL)
        {
            DbgPrint("[KPAM-IMAGE-ALERT] Monitored PID %lu loaded image: %wZ\n", pid, FullImageName);
            eventData.Data.ImageEvent.HasPath = TRUE;
            KpamSetEventText(&eventData, FullImageName);
        }
        else
        {
            DbgPrint("[KPAM-IMAGE-ALERT] Monitored PID %lu loaded image (Name NULL, BaseAddress: 0x%p)\n", pid, ImageInfo ? ImageInfo->ImageBase : NULL);
        }

        AddEventToList(&eventData);
    }
}
