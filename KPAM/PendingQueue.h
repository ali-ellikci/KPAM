#pragma once

#include <ntddk.h>

extern IO_CSQ g_Csq;
extern KSPIN_LOCK g_CsqSpinLock;
extern LIST_ENTRY g_PendingIrpList;

VOID CsqInsertIrp(PIO_CSQ Csq, PIRP Irp);
VOID CsqRemoveIrp(PIO_CSQ Csq, PIRP Irp);
PIRP CsqPeekNextIrp(PIO_CSQ Csq, PIRP Irp, PVOID PeekContext);
VOID CsqAcquireLock(PIO_CSQ Csq, PKIRQL Irql);
VOID CsqReleaseLock(PIO_CSQ Csq, KIRQL Irql);
VOID CsqCompleteCanceledIrp(PIO_CSQ Csq, PIRP Irp);

VOID InitializePendingCsq(VOID);