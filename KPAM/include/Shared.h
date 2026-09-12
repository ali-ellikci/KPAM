#pragma once

#define KPAM_DEVICE_NAME      L"\\Device\\KPAM"
#define KPAM_SYMBOLIC_LINK    L"\\DosDevices\\KPAM"
#define KPAM_USER_LINK        L"\\\\.\\KPAM"

#define KPAM_CTL_BASE 0x8000
#define IOCTL_KPAM_REGISTER_PID \
    CTL_CODE(KPAM_CTL_BASE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KPAM_GET_NEXT_EVENT \
    CTL_CODE(KPAM_CTL_BASE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define KPAM_MAX_EVENT_TEXT_CHARS 512
#define KPAM_ADDRESS_FAMILY_IPV4 2
#define KPAM_ADDRESS_FAMILY_IPV6 23

typedef struct _KPAM_REGISTER_DATA {
    ULONG ProcessId;
} KPAM_REGISTER_DATA, *PKPAM_REGISTER_DATA;

enum KPAM_EVENT_TYPE : ULONG {
    KpamEventProcess,
    KpamEventThread,
    KpamEventRegistry,
    KpamEventImage,
    KpamEventHandle,
    KpamEventFile,
    KpamEventNetwork
};

enum KPAM_EVENT_ACTION : ULONG {
    KpamActionNone,
    KpamActionCreate,
    KpamActionTerminate,
    KpamActionRegistrySetValue,
    KpamActionRegistryCreateKey,
    KpamActionProcessHandle,
    KpamActionThreadHandle
};

union KPAM_EVENT_PAYLOAD {
    struct {
        ULONG RelatedProcessId;
        ULONG Action;
    } ProcessEvent;

    struct {
        ULONG ThreadId;
        ULONG Action;
    } ThreadEvent;

    struct {
        ULONGLONG KeyHandle;
        ULONG Action;
    } RegistryEvent;

    struct {
        ULONGLONG ImageBaseAddress;
        ULONG HasPath;
    } ImageEvent;

    struct {
        ULONG ObjectKind;
        ULONG TargetProcessId;
        ULONG TargetThreadId;
        ULONG OwnerProcessId;
        ULONG DesiredAccess;
    } HandleEvent;

    struct {
        ULONG Reserved;
    } FileEvent;

    struct {
        ULONG AddressFamily;
        ULONG Protocol;
        USHORT RemotePort;
        USHORT Reserved;
        UCHAR RemoteAddress[16];
    } NetworkEvent;
};

typedef struct _KPAM_EVENT_DATA {
    ULONG Size;
    KPAM_EVENT_TYPE Type;
    ULONG ProcessId;
    ULONG TextLength;
    LARGE_INTEGER Timestamp;
    KPAM_EVENT_PAYLOAD Data;
    WCHAR Text[KPAM_MAX_EVENT_TEXT_CHARS];
} KPAM_EVENT_DATA, *PKPAM_EVENT_DATA;
