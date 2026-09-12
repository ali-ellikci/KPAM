
#include "FileLogic.h"

#include "NetworkLogic.h"
#include "Communication.h"
#include "ThreadLogic.h"
#include "RegistryLogic.h"
#include "ImageLogic.h"
#include "HandleLogic.h"

KPAM_GLOBAL_CONTEXT g_KpamContext;

void DriverUnload(PDRIVER_OBJECT DriverObject);

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	DbgPrint("[KPAM] Driver loading...\n");
	UNREFERENCED_PARAMETER(RegistryPath);

	PDEVICE_OBJECT DeviceObject = nullptr;
	UNICODE_STRING deviceName = RTL_CONSTANT_STRING(KPAM_DEVICE_NAME);
	UNICODE_STRING symbolicLinkName = RTL_CONSTANT_STRING(KPAM_SYMBOLIC_LINK);

	InitializeKpamContext();
	InitializeEventList();
	InitializePendingCsq();

	NTSTATUS status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	g_KpamContext.DeviceObject = DeviceObject; 

	status = IoCreateSymbolicLink(&symbolicLinkName, &deviceName);
	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(DeviceObject);
		return status;
	}

	DriverObject->DriverUnload = DriverUnload;

	for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		DriverObject->MajorFunction[i] = UnsuportedIOCTL;
	}

	DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateCloseIOCTL;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateCloseIOCTL;
	DriverObject->MajorFunction[IRP_MJ_CLEANUP] = CleanupIOCTL;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControlIOCTL;

	
	status = PsSetCreateProcessNotifyRoutineEx(KpamCreateProcessNotifyRoutineEx, FALSE);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[KPAM] PsSetCreateProcessNotifyRoutineEx failed: 0x%X\n", status);
		IoDeleteSymbolicLink(&symbolicLinkName);
		IoDeleteDevice(DeviceObject);
		return status;
	}

	
	status = PsSetCreateThreadNotifyRoutine(KpamCreateThreadNotifyRoutine);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[KPAM] PsSetCreateThreadNotifyRoutine failed: 0x%X\n", status);
		PsSetCreateProcessNotifyRoutineEx(KpamCreateProcessNotifyRoutineEx, TRUE);
		IoDeleteSymbolicLink(&symbolicLinkName);
		IoDeleteDevice(DeviceObject);
		return status;
	}

	
	UNICODE_STRING altitude = RTL_CONSTANT_STRING(L"320000"); 
	status = CmRegisterCallbackEx(KpamRegistryCallback, &altitude, DriverObject, nullptr, &g_RegCookie, nullptr);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[KPAM] CmRegisterCallbackEx failed: 0x%X\n", status);
		PsRemoveCreateThreadNotifyRoutine(KpamCreateThreadNotifyRoutine);
		PsSetCreateProcessNotifyRoutineEx(KpamCreateProcessNotifyRoutineEx, TRUE);
		IoDeleteSymbolicLink(&symbolicLinkName);
		IoDeleteDevice(DeviceObject);
		return status;
	}

	
	status = PsSetLoadImageNotifyRoutine(KpamLoadImageNotifyRoutine);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[KPAM] PsSetLoadImageNotifyRoutine failed: 0x%X\n", status);
		CmUnRegisterCallback(g_RegCookie);
		PsRemoveCreateThreadNotifyRoutine(KpamCreateThreadNotifyRoutine);
		PsSetCreateProcessNotifyRoutineEx(KpamCreateProcessNotifyRoutineEx, TRUE);
		IoDeleteSymbolicLink(&symbolicLinkName);
		IoDeleteDevice(DeviceObject);
		return status;
	}

	
	status = KpamRegisterObCallbacks(DriverObject);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[KPAM] KpamRegisterObCallbacks failed: 0x%X\n", status);
		PsRemoveLoadImageNotifyRoutine(KpamLoadImageNotifyRoutine);
		CmUnRegisterCallback(g_RegCookie);
		PsRemoveCreateThreadNotifyRoutine(KpamCreateThreadNotifyRoutine);
		PsSetCreateProcessNotifyRoutineEx(KpamCreateProcessNotifyRoutineEx, TRUE);
		IoDeleteSymbolicLink(&symbolicLinkName);
		IoDeleteDevice(DeviceObject);
		return status;
	}

	
	status = KpamRegisterMinifilter(DriverObject);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[KPAM] KpamRegisterMinifilter failed: 0x%X\n", status);
		KpamUnregisterObCallbacks();
		PsRemoveLoadImageNotifyRoutine(KpamLoadImageNotifyRoutine);
		CmUnRegisterCallback(g_RegCookie);
		PsRemoveCreateThreadNotifyRoutine(KpamCreateThreadNotifyRoutine);
		PsSetCreateProcessNotifyRoutineEx(KpamCreateProcessNotifyRoutineEx, TRUE);
		IoDeleteSymbolicLink(&symbolicLinkName);
		IoDeleteDevice(DeviceObject);
		return status;
	}

	
	status = KpamRegisterNetworkCallout(DeviceObject);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[KPAM] KpamRegisterNetworkCallout failed: 0x%X\n", status);
		KpamUnregisterMinifilter();
		KpamUnregisterObCallbacks();
		PsRemoveLoadImageNotifyRoutine(KpamLoadImageNotifyRoutine);
		CmUnRegisterCallback(g_RegCookie);
		PsRemoveCreateThreadNotifyRoutine(KpamCreateThreadNotifyRoutine);
		PsSetCreateProcessNotifyRoutineEx(KpamCreateProcessNotifyRoutineEx, TRUE);
		IoDeleteSymbolicLink(&symbolicLinkName);
		IoDeleteDevice(DeviceObject);
		return status;
	}

	DbgPrint("[KPAM] Driver loaded: Process/Thread/Registry/Image/Handle/File/Network Routines registered.\n");
	return STATUS_SUCCESS;
}

void DriverUnload(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	DbgPrint("[KPAM] Driver unloading...\n");

	
	KpamUnregisterNetworkCallout(); 
	KpamUnregisterMinifilter();
	KpamUnregisterObCallbacks();
	PsRemoveLoadImageNotifyRoutine(KpamLoadImageNotifyRoutine);
	CmUnRegisterCallback(g_RegCookie);
	PsRemoveCreateThreadNotifyRoutine(KpamCreateThreadNotifyRoutine);
	PsSetCreateProcessNotifyRoutineEx(KpamCreateProcessNotifyRoutineEx, TRUE);

	UNICODE_STRING symbolicLinkName = RTL_CONSTANT_STRING(KPAM_SYMBOLIC_LINK);
	IoDeleteSymbolicLink(&symbolicLinkName);

	KpamCancelPendingEvents();
	ClearEventList();
	KpamClearProcessList();

	
	if (g_KpamContext.DeviceObject != nullptr)
	{
		IoDeleteDevice(g_KpamContext.DeviceObject);
	}
	DbgPrint("[KPAM] Driver unloaded successfully.\n");
}
