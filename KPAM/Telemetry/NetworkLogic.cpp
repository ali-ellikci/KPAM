

#define NDIS_SUPPORT_NDIS6 1
#include <ndis.h>
#include <initguid.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include "NetworkLogic.h"
#include "ProcessLogic.h"
#include "EventList.h"

static const GUID KPAM_NET_CALLOUT_V4 =
    { 0xa1b2c3d4, 0xe5f6, 0x7890, { 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90 } };

static const GUID KPAM_NET_CALLOUT_V6 =
    { 0xb1c2d3e4, 0xf5a6, 0x8901, { 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x91 } };

static const GUID KPAM_NET_SUBLAYER =
    { 0xc1d2e3f4, 0xa5b6, 0x9012, { 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0x02 } };

static HANDLE  g_EngineHandle = NULL;
static UINT32  g_CalloutIdV4  = 0;
static UINT32  g_CalloutIdV6  = 0;
static UINT64  g_FilterIdV4   = 0;
static UINT64  g_FilterIdV6   = 0;
static BOOLEAN g_SublayerAdded = FALSE;

static NTSTATUS NTAPI KpamNetNotifyFn(
    _In_        FWPS_CALLOUT_NOTIFY_TYPE    notifyType,
    _In_ const  GUID*                       filterKey,
    _Inout_     FWPS_FILTER0*               filter)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

static VOID NTAPI KpamNetClassifyV4(
    _In_        const FWPS_INCOMING_VALUES0*          inFixedValues,
    _In_        const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ VOID*                                 layerData,
    _In_        const FWPS_FILTER0*                   filter,
    _In_        UINT64                                flowContext,
    _Inout_     FWPS_CLASSIFY_OUT0*                   classifyOut)
{
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    classifyOut->actionType = FWP_ACTION_PERMIT;

    if (!(inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID))
        return;

    ULONG pid = (ULONG)inMetaValues->processId;

    if (!KpamIsProcessMonitored(pid))
        return;

    UINT32 remoteIp   = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32;
    UINT16 remotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value.uint16;
    UINT8  protocol   = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL].value.uint8;

    DbgPrint("[KPAM-NET] PID %lu | IPv4 | Protocol:%u | Target: %u.%u.%u.%u:%u\n",
        pid,
        (UINT32)protocol,
        (remoteIp >> 24) & 0xFF,
        (remoteIp >> 16) & 0xFF,
        (remoteIp >> 8)  & 0xFF,
         remoteIp        & 0xFF,
        (UINT32)remotePort);

    KPAM_EVENT_DATA eventData;
    KpamInitializeEvent(&eventData, KpamEventNetwork, pid);
    eventData.Data.NetworkEvent.AddressFamily = KPAM_ADDRESS_FAMILY_IPV4;
    eventData.Data.NetworkEvent.Protocol = protocol;
    eventData.Data.NetworkEvent.RemotePort = remotePort;
    eventData.Data.NetworkEvent.RemoteAddress[0] = (remoteIp >> 24) & 0xFF;
    eventData.Data.NetworkEvent.RemoteAddress[1] = (remoteIp >> 16) & 0xFF;
    eventData.Data.NetworkEvent.RemoteAddress[2] = (remoteIp >> 8) & 0xFF;
    eventData.Data.NetworkEvent.RemoteAddress[3] = remoteIp & 0xFF;
    AddEventToList(&eventData);
}

static VOID NTAPI KpamNetClassifyV6(
    _In_        const FWPS_INCOMING_VALUES0*          inFixedValues,
    _In_        const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ VOID*                                 layerData,
    _In_        const FWPS_FILTER0*                   filter,
    _In_        UINT64                                flowContext,
    _Inout_     FWPS_CLASSIFY_OUT0*                   classifyOut)
{
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    classifyOut->actionType = FWP_ACTION_PERMIT;

    if (!(inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID))
        return;

    ULONG pid = (ULONG)inMetaValues->processId;

    if (!KpamIsProcessMonitored(pid))
        return;

    UINT16       remotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_PORT].value.uint16;
    UINT8        protocol   = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_PROTOCOL].value.uint8;
    const UINT8* addr       = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS].value.byteArray16->byteArray16;

    DbgPrint("[KPAM-NET] PID %lu | IPv6 | Protocol:%u | Target: "
             "[%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x]:%u\n",
        pid, (UINT32)protocol,
        addr[0],  addr[1],  addr[2],  addr[3],
        addr[4],  addr[5],  addr[6],  addr[7],
        addr[8],  addr[9],  addr[10], addr[11],
        addr[12], addr[13], addr[14], addr[15],
        (UINT32)remotePort);

    KPAM_EVENT_DATA eventData;
    KpamInitializeEvent(&eventData, KpamEventNetwork, pid);
    eventData.Data.NetworkEvent.AddressFamily = KPAM_ADDRESS_FAMILY_IPV6;
    eventData.Data.NetworkEvent.Protocol = protocol;
    eventData.Data.NetworkEvent.RemotePort = remotePort;
    RtlCopyMemory(eventData.Data.NetworkEvent.RemoteAddress, addr, 16);
    AddEventToList(&eventData);
}

static NTSTATUS RegisterOneCallout(
    HANDLE          engineHandle,
    PDEVICE_OBJECT  deviceObject,
    const GUID*     calloutKey,
    const GUID*     layerKey,
    FWPS_CALLOUT_CLASSIFY_FN0 classifyFn,
    UINT32*         outCalloutId)
{

    FWPS_CALLOUT0 fwpsCallout = { 0 };
    fwpsCallout.calloutKey   = *calloutKey;
    fwpsCallout.classifyFn   = classifyFn;
    fwpsCallout.notifyFn     = KpamNetNotifyFn;

    NTSTATUS status = FwpsCalloutRegister0(deviceObject, &fwpsCallout, outCalloutId);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[KPAM] FwpsCalloutRegister0 failed: 0x%X\n", status);
        return status;
    }

    FWPM_CALLOUT0 fwpmCallout = { 0 };
    fwpmCallout.calloutKey    = *calloutKey;
    fwpmCallout.applicableLayer = *layerKey;
    fwpmCallout.displayData.name = (PWSTR)L"KPAM Network Callout";

    status = FwpmCalloutAdd0(engineHandle, &fwpmCallout, NULL, NULL);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS)
    {
        DbgPrint("[KPAM] FwpmCalloutAdd0 failed: 0x%X\n", status);
        FwpsCalloutUnregisterByKey0(calloutKey);
        *outCalloutId = 0;
        return status;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS AddFilter(
    HANDLE      engineHandle,
    const GUID* calloutKey,
    const GUID* layerKey,
    UINT64*     outFilterId)
{
    FWPM_FILTER0 filter = { 0 };
    filter.layerKey          = *layerKey;
    filter.action.type       = FWP_ACTION_CALLOUT_INSPECTION;
    filter.action.calloutKey = *calloutKey;
    filter.weight.type       = FWP_EMPTY;
    filter.subLayerKey       = KPAM_NET_SUBLAYER;
    filter.displayData.name  = (PWSTR)L"KPAM Network Filter";

    NTSTATUS status = FwpmFilterAdd0(engineHandle, &filter, NULL, outFilterId);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[KPAM] FwpmFilterAdd0 failed: 0x%X\n", status);
    }
    return status;
}

NTSTATUS KpamRegisterNetworkCallout(PDEVICE_OBJECT DeviceObject)
{
    NTSTATUS status;

    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &g_EngineHandle);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[KPAM] FwpmEngineOpen0 failed: 0x%X\n", status);
        return status;
    }

    status = FwpmTransactionBegin0(g_EngineHandle, 0);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[KPAM] FwpmTransactionBegin0 failed: 0x%X\n", status);
        FwpmEngineClose0(g_EngineHandle);
        g_EngineHandle = NULL;
        return status;
    }

    FWPM_SUBLAYER0 sublayer = { 0 };
    sublayer.subLayerKey = KPAM_NET_SUBLAYER;
    sublayer.displayData.name = (PWSTR)L"KPAM Sublayer";
    sublayer.weight = 0x100;

    status = FwpmSubLayerAdd0(g_EngineHandle, &sublayer, NULL);
    if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS)
    {
        DbgPrint("[KPAM] FwpmSubLayerAdd0 failed: 0x%X\n", status);
        FwpmTransactionAbort0(g_EngineHandle);
        FwpmEngineClose0(g_EngineHandle);
        g_EngineHandle = NULL;
        return status;
    }
    if (NT_SUCCESS(status))
        g_SublayerAdded = TRUE;

    status = RegisterOneCallout(g_EngineHandle, DeviceObject,
        &KPAM_NET_CALLOUT_V4, &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        KpamNetClassifyV4, &g_CalloutIdV4);
    if (!NT_SUCCESS(status))
    {
        FwpmTransactionAbort0(g_EngineHandle);
        FwpmEngineClose0(g_EngineHandle);
        g_EngineHandle = NULL;
        return status;
    }

    status = RegisterOneCallout(g_EngineHandle, DeviceObject,
        &KPAM_NET_CALLOUT_V6, &FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        KpamNetClassifyV6, &g_CalloutIdV6);
    if (!NT_SUCCESS(status))
    {
        FwpsCalloutUnregisterById0(g_CalloutIdV4);
        g_CalloutIdV4 = 0;
        FwpmTransactionAbort0(g_EngineHandle);
        FwpmEngineClose0(g_EngineHandle);
        g_EngineHandle = NULL;
        return status;
    }

    status = AddFilter(g_EngineHandle, &KPAM_NET_CALLOUT_V4,
        &FWPM_LAYER_ALE_AUTH_CONNECT_V4, &g_FilterIdV4);
    if (!NT_SUCCESS(status))
    {
        FwpsCalloutUnregisterById0(g_CalloutIdV6); g_CalloutIdV6 = 0;
        FwpsCalloutUnregisterById0(g_CalloutIdV4); g_CalloutIdV4 = 0;
        FwpmTransactionAbort0(g_EngineHandle);
        FwpmEngineClose0(g_EngineHandle);
        g_EngineHandle = NULL;
        return status;
    }

    status = AddFilter(g_EngineHandle, &KPAM_NET_CALLOUT_V6,
        &FWPM_LAYER_ALE_AUTH_CONNECT_V6, &g_FilterIdV6);
    if (!NT_SUCCESS(status))
    {
        FwpmFilterDeleteById0(g_EngineHandle, g_FilterIdV4); g_FilterIdV4 = 0;
        FwpsCalloutUnregisterById0(g_CalloutIdV6); g_CalloutIdV6 = 0;
        FwpsCalloutUnregisterById0(g_CalloutIdV4); g_CalloutIdV4 = 0;
        FwpmTransactionAbort0(g_EngineHandle);
        FwpmEngineClose0(g_EngineHandle);
        g_EngineHandle = NULL;
        return status;
    }

    status = FwpmTransactionCommit0(g_EngineHandle);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[KPAM] FwpmTransactionCommit0 failed: 0x%X\n", status);
        FwpmTransactionAbort0(g_EngineHandle);
        FwpsCalloutUnregisterById0(g_CalloutIdV6); g_CalloutIdV6 = 0;
        FwpsCalloutUnregisterById0(g_CalloutIdV4); g_CalloutIdV4 = 0;
        FwpmEngineClose0(g_EngineHandle);
        g_EngineHandle = NULL;
        return status;
    }

    DbgPrint("[KPAM] WFP network callouts (IPv4 + IPv6) registered successfully.\n");
    return STATUS_SUCCESS;
}

void KpamUnregisterNetworkCallout()
{
    if (g_EngineHandle != NULL)
    {

        if (g_FilterIdV4 != 0)
        {
            FwpmFilterDeleteById0(g_EngineHandle, g_FilterIdV4);
            g_FilterIdV4 = 0;
        }
        if (g_FilterIdV6 != 0)
        {
            FwpmFilterDeleteById0(g_EngineHandle, g_FilterIdV6);
            g_FilterIdV6 = 0;
        }

        FwpmCalloutDeleteByKey0(g_EngineHandle, &KPAM_NET_CALLOUT_V4);
        FwpmCalloutDeleteByKey0(g_EngineHandle, &KPAM_NET_CALLOUT_V6);

        if (g_SublayerAdded)
        {
            FwpmSubLayerDeleteByKey0(g_EngineHandle, &KPAM_NET_SUBLAYER);
            g_SublayerAdded = FALSE;
        }

        FwpmEngineClose0(g_EngineHandle);
        g_EngineHandle = NULL;
    }

    if (g_CalloutIdV4 != 0)
    {
        FwpsCalloutUnregisterById0(g_CalloutIdV4);
        g_CalloutIdV4 = 0;
    }
    if (g_CalloutIdV6 != 0)
    {
        FwpsCalloutUnregisterById0(g_CalloutIdV6);
        g_CalloutIdV6 = 0;
    }

    DbgPrint("[KPAM] WFP network callouts unregistered.\n");
}
