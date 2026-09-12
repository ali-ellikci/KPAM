#include "Communication.h"

NTSTATUS UnsuportedIOCTL(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS CreateCloseIOCTL(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS CleanupIOCTL(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PFILE_OBJECT fileObject = IoGetCurrentIrpStackLocation(Irp)->FileObject;
    PIRP pendingIrp;
    while ((pendingIrp = IoCsqRemoveNextIrp(&g_Csq, fileObject)) != nullptr)
    {
        pendingIrp->IoStatus.Status = STATUS_CANCELLED;
        pendingIrp->IoStatus.Information = 0;
        IoCompleteRequest(pendingIrp, IO_NO_INCREMENT);
    }

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DeviceControlIOCTL(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    PIO_STACK_LOCATION ioStackLocation = IoGetCurrentIrpStackLocation(Irp);
    Irp->IoStatus.Information = 0;

    switch (ioStackLocation->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_KPAM_REGISTER_PID:
    {
        if (ioStackLocation->Parameters.DeviceIoControl.InputBufferLength <
            sizeof(KPAM_REGISTER_DATA))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        PKPAM_REGISTER_DATA data =
            static_cast<PKPAM_REGISTER_DATA>(Irp->AssociatedIrp.SystemBuffer);
        if (data == nullptr)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        DbgPrint("[KPAM] KPAM_REGISTER_PID received: PID = %lu\n", data->ProcessId);
        status = KpamAddProcess(data->ProcessId);
        break;
    }

    case IOCTL_KPAM_GET_NEXT_EVENT:
    {
        ULONG outputBufferLength =
            ioStackLocation->Parameters.DeviceIoControl.OutputBufferLength;
        PKPAM_EVENT_DATA userBuffer =
            static_cast<PKPAM_EVENT_DATA>(Irp->AssociatedIrp.SystemBuffer);

        if (userBuffer == nullptr || outputBufferLength < sizeof(KPAM_EVENT_DATA))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (GetNextEventFromList(userBuffer))
        {
            status = STATUS_SUCCESS;
            Irp->IoStatus.Information = sizeof(KPAM_EVENT_DATA);
            break;
        }

        IoMarkIrpPending(Irp);
        IoCsqInsertIrp(&g_Csq, Irp, nullptr);

        KpamTryCompletePendingEvent();
        return STATUS_PENDING;
    }

    default:
        return UnsuportedIOCTL(DeviceObject, Irp);
    }

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}
