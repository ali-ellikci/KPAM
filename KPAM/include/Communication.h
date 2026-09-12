#pragma once
#include "KpamData.h"
#include "ProcessLogic.h"
#include "PendingQueue.h"
#include "EventList.h"

NTSTATUS UnsuportedIOCTL(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS CreateCloseIOCTL(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS CleanupIOCTL(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS DeviceControlIOCTL(PDEVICE_OBJECT DeviceObject, PIRP Irp);
