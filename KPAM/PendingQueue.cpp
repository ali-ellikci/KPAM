#include "PendingQueue.h"

IO_CSQ g_Csq;
KSPIN_LOCK g_CsqSpinLock;
LIST_ENTRY g_PendingIrpList;

VOID InitializePendingCsq(VOID) {
    InitializeListHead(&g_PendingIrpList);
    KeInitializeSpinLock(&g_CsqSpinLock);

    IoCsqInitialize(
        &g_Csq,
        CsqInsertIrp,
        CsqRemoveIrp,
        CsqPeekNextIrp, 
        CsqAcquireLock,
        CsqReleaseLock,
        CsqCompleteCanceledIrp
    );
}

VOID CsqInsertIrp(PIO_CSQ Csq, PIRP Irp) {
    UNREFERENCED_PARAMETER(Csq);
    InsertTailList(&g_PendingIrpList, &Irp->Tail.Overlay.ListEntry);
}

VOID CsqRemoveIrp(PIO_CSQ Csq, PIRP Irp) {
    UNREFERENCED_PARAMETER(Csq);
    RemoveEntryList(&Irp->Tail.Overlay.ListEntry);
}

PIRP CsqPeekNextIrp(PIO_CSQ Csq, PIRP Irp, PVOID PeekContext) {
    UNREFERENCED_PARAMETER(Csq);

    PLIST_ENTRY listHead = &g_PendingIrpList;
    PLIST_ENTRY listEntry = NULL;
    PIRP nextIrp = NULL;
    PIO_STACK_LOCATION irpSp = NULL;

    
    
    if (Irp == NULL) {
        listEntry = listHead->Flink;
    }
    else {
        listEntry = Irp->Tail.Overlay.ListEntry.Flink;
    }

    for (; listEntry != listHead; listEntry = listEntry->Flink) {
        nextIrp = CONTAINING_RECORD(listEntry, IRP, Tail.Overlay.ListEntry);

        
        if (PeekContext == NULL) {
            return nextIrp;
        }

        
        irpSp = IoGetCurrentIrpStackLocation(nextIrp);
        if (irpSp->FileObject == PeekContext) {
            return nextIrp;
        }
    }

    return NULL;
}

VOID CsqAcquireLock(PIO_CSQ Csq, PKIRQL Irql) {
    UNREFERENCED_PARAMETER(Csq);
    KeAcquireSpinLock(&g_CsqSpinLock, Irql);
}

VOID CsqReleaseLock(PIO_CSQ Csq, KIRQL Irql) {
    UNREFERENCED_PARAMETER(Csq);
    KeReleaseSpinLock(&g_CsqSpinLock, Irql);
}

VOID CsqCompleteCanceledIrp(PIO_CSQ Csq, PIRP Irp) {
    UNREFERENCED_PARAMETER(Csq);
    Irp->IoStatus.Status = STATUS_CANCELLED;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
}