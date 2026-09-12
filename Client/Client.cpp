#define NOMINMAX
#include <Windows.h>

#include <algorithm>
#include <cstdio>
#include <iostream>
#include <string>

#include "../KPAM/include/Shared.h"

namespace
{
constexpr DWORD KPAM_DRAIN_TIMEOUT_MS = 1000;

enum class ReceiveResult
{
    Completed,
    Pending,
    Failed
};

std::wstring GetClientDirectory()
{
    wchar_t path[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, path, MAX_PATH);

    std::wstring fullPath(path);
    const size_t lastSlash = fullPath.find_last_of(L"\\/");
    return lastSlash == std::wstring::npos
        ? std::wstring()
        : fullPath.substr(0, lastSlash + 1);
}

bool FileExists(const std::wstring& filePath)
{
    const DWORD attributes = GetFileAttributesW(filePath.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES &&
        !(attributes & FILE_ATTRIBUTE_DIRECTORY);
}

std::wstring EventText(const KPAM_EVENT_DATA& eventData)
{
    const ULONG length = std::min(
        eventData.TextLength,
        static_cast<ULONG>(KPAM_MAX_EVENT_TEXT_CHARS - 1));
    return std::wstring(eventData.Text, eventData.Text + length);
}

void PrintTelemetryEvent(const KPAM_EVENT_DATA& eventData)
{
    const std::wstring text = EventText(eventData);

    switch (eventData.Type)
    {
    case KpamEventProcess:
        if (eventData.Data.ProcessEvent.Action == KpamActionCreate)
        {
            std::wprintf(
                L"[KPAM-ALERT] Monitored PID %lu -> New PID: %lu | Path: %ls\n",
                eventData.ProcessId,
                eventData.Data.ProcessEvent.RelatedProcessId,
                text.c_str());
        }
        else if (eventData.Data.ProcessEvent.Action == KpamActionTerminate)
        {
            std::wprintf(
                L"[KPAM] Monitored PID %lu is terminating\n",
                eventData.ProcessId);
        }
        break;

    case KpamEventThread:
        if (eventData.Data.ThreadEvent.Action == KpamActionCreate)
        {
            std::wprintf(
                L"[KPAM-ALERT] Thread Created in Monitored Process! PID: %lu -> TID: %lu\n",
                eventData.ProcessId,
                eventData.Data.ThreadEvent.ThreadId);
        }
        else if (eventData.Data.ThreadEvent.Action == KpamActionTerminate)
        {
            std::wprintf(
                L"[KPAM] Thread Terminated in Monitored Process! PID: %lu -> TID: %lu\n",
                eventData.ProcessId,
                eventData.Data.ThreadEvent.ThreadId);
        }
        break;

    case KpamEventRegistry:
        if (eventData.Data.RegistryEvent.Action == KpamActionRegistrySetValue)
        {
            std::wprintf(
                L"[KPAM-REG] Monitored process (PID: %lu) is writing registry value: %ls\n",
                eventData.ProcessId,
                text.c_str());
        }
        else if (eventData.Data.RegistryEvent.Action == KpamActionRegistryCreateKey)
        {
            std::wprintf(
                L"[KPAM-REG] Monitored process (PID: %lu) is creating a new key: %ls\n",
                eventData.ProcessId,
                text.c_str());
        }
        break;

    case KpamEventImage:
        if (eventData.Data.ImageEvent.HasPath)
        {
            std::wprintf(
                L"[KPAM-IMAGE-ALERT] Monitored PID %lu loaded image: %ls\n",
                eventData.ProcessId,
                text.c_str());
        }
        else
        {
            const void* imageBase = reinterpret_cast<const void*>(
                static_cast<ULONG_PTR>(eventData.Data.ImageEvent.ImageBaseAddress));
            std::wprintf(
                L"[KPAM-IMAGE-ALERT] Monitored PID %lu loaded image (Name NULL, BaseAddress: 0x%p)\n",
                eventData.ProcessId,
                imageBase);
        }
        break;

    case KpamEventHandle:
        if (eventData.Data.HandleEvent.ObjectKind == KpamActionProcessHandle)
        {
            std::wprintf(
                L"[KPAM-HANDLE-ALERT] Monitored PID %lu requested process handle to PID %lu (DesiredAccess: 0x%X)\n",
                eventData.ProcessId,
                eventData.Data.HandleEvent.TargetProcessId,
                eventData.Data.HandleEvent.DesiredAccess);
        }
        else if (eventData.Data.HandleEvent.ObjectKind == KpamActionThreadHandle)
        {
            std::wprintf(
                L"[KPAM-HANDLE-ALERT] Monitored PID %lu requested thread handle to TID %lu (Owner PID %lu) (DesiredAccess: 0x%X)\n",
                eventData.ProcessId,
                eventData.Data.HandleEvent.TargetThreadId,
                eventData.Data.HandleEvent.OwnerProcessId,
                eventData.Data.HandleEvent.DesiredAccess);
        }
        break;

    case KpamEventFile:
        std::wprintf(
            L"[KPAM-FILE] PID %lu opened file: %ls\n",
            eventData.ProcessId,
            text.c_str());
        break;

    case KpamEventNetwork:
    {
        const UCHAR* address = eventData.Data.NetworkEvent.RemoteAddress;
        if (eventData.Data.NetworkEvent.AddressFamily == KPAM_ADDRESS_FAMILY_IPV4)
        {
            std::wprintf(
                L"[KPAM-NET] PID %lu | IPv4 | Protocol:%u | Target: %u.%u.%u.%u:%u\n",
                eventData.ProcessId,
                eventData.Data.NetworkEvent.Protocol,
                address[0], address[1], address[2], address[3],
                eventData.Data.NetworkEvent.RemotePort);
        }
        else if (eventData.Data.NetworkEvent.AddressFamily == KPAM_ADDRESS_FAMILY_IPV6)
        {
            std::wprintf(
                L"[KPAM-NET] PID %lu | IPv6 | Protocol:%u | Target: "
                L"[%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x]:%u\n",
                eventData.ProcessId,
                eventData.Data.NetworkEvent.Protocol,
                address[0], address[1], address[2], address[3],
                address[4], address[5], address[6], address[7],
                address[8], address[9], address[10], address[11],
                address[12], address[13], address[14], address[15],
                eventData.Data.NetworkEvent.RemotePort);
        }
        break;
    }

    default:
        std::wprintf(L"[KPAM-Client] Unknown event type: %lu\n", eventData.Type);
        break;
    }

    std::fflush(stdout);
}

bool ValidateAndPrintEvent(KPAM_EVENT_DATA& eventData, DWORD bytesReturned)
{
    if (bytesReturned != sizeof(KPAM_EVENT_DATA) ||
        eventData.Size != sizeof(KPAM_EVENT_DATA) ||
        eventData.Type > KpamEventNetwork ||
        eventData.TextLength >= KPAM_MAX_EVENT_TEXT_CHARS)
    {
        std::wcout << L"[KPAM-Client] ERROR: Received an invalid event packet. Bytes="
            << bytesReturned << L", Size=" << eventData.Size << std::endl;
        return false;
    }

    eventData.Text[eventData.TextLength] = L'\0';
    PrintTelemetryEvent(eventData);
    return true;
}

bool SendRegisterPid(HANDLE device, DWORD processId)
{
    KPAM_REGISTER_DATA registerData = {};
    registerData.ProcessId = processId;

    OVERLAPPED overlapped = {};
    overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (overlapped.hEvent == nullptr)
    {
        return false;
    }

    DWORD bytesReturned = 0;
    BOOL result = DeviceIoControl(
        device,
        IOCTL_KPAM_REGISTER_PID,
        &registerData,
        sizeof(registerData),
        nullptr,
        0,
        &bytesReturned,
        &overlapped);

    if (!result && GetLastError() == ERROR_IO_PENDING)
    {
        result = GetOverlappedResult(device, &overlapped, &bytesReturned, TRUE);
    }

    const DWORD error = result ? ERROR_SUCCESS : GetLastError();
    CloseHandle(overlapped.hEvent);

    if (!result)
    {
        SetLastError(error);
        return false;
    }
    return true;
}

ReceiveResult PostReceive(
    HANDLE device,
    OVERLAPPED& overlapped,
    KPAM_EVENT_DATA& eventData,
    DWORD& bytesReturned)
{
    const HANDLE completionEvent = overlapped.hEvent;
    ZeroMemory(&overlapped, sizeof(overlapped));
    overlapped.hEvent = completionEvent;
    ResetEvent(completionEvent);
    ZeroMemory(&eventData, sizeof(eventData));
    bytesReturned = 0;

    const BOOL result = DeviceIoControl(
        device,
        IOCTL_KPAM_GET_NEXT_EVENT,
        nullptr,
        0,
        &eventData,
        sizeof(eventData),
        &bytesReturned,
        &overlapped);

    if (result)
    {
        return ReceiveResult::Completed;
    }

    if (GetLastError() == ERROR_IO_PENDING)
    {
        return ReceiveResult::Pending;
    }

    return ReceiveResult::Failed;
}
}

int wmain(int argc, wchar_t* argv[])
{
    if (argc < 2)
    {
        std::wcout << L"[KPAM-Client] Usage: Client.exe <target_executable_path>" << std::endl;
        std::wcout << L"  Example: Client.exe sample.exe" << std::endl;
        std::wcout << L"  Example: Client.exe C:\\samples\\sample.exe" << std::endl;
        return 1;
    }

    std::wstring targetPath(argv[1]);
    if (targetPath.length() < 2 ||
        (targetPath[1] != L':' && targetPath[0] != L'\\'))
    {
        targetPath = GetClientDirectory() + targetPath;
        std::wcout << L"[KPAM-Client] Relative path supplied; resolving from the client directory: "
            << targetPath << std::endl;
    }

    if (!FileExists(targetPath))
    {
        std::wcout << L"[KPAM-Client] ERROR: File not found: "
            << targetPath << std::endl;
        return 1;
    }

    STARTUPINFOW startupInfo = {};
    PROCESS_INFORMATION processInfo = {};
    startupInfo.cb = sizeof(startupInfo);

    if (!CreateProcessW(
        targetPath.c_str(),
        nullptr,
        nullptr,
        nullptr,
        FALSE,
        CREATE_SUSPENDED,
        nullptr,
        nullptr,
        &startupInfo,
        &processInfo))
    {
        std::wcout << L"[KPAM-Client] ERROR: Failed to create the target process. Error code: "
            << GetLastError() << std::endl;
        return 1;
    }

    const DWORD processId = processInfo.dwProcessId;
    std::wcout << L"[KPAM-Client] Target process started suspended. PID: "
        << processId << std::endl;

    HANDLE device = CreateFileW(
        KPAM_USER_LINK,
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED,
        nullptr);

    if (device == INVALID_HANDLE_VALUE)
    {
        std::wcout << L"[KPAM-Client] ERROR: Failed to connect to the driver. Error code: "
            << GetLastError() << std::endl;
        TerminateProcess(processInfo.hProcess, 1);
        CloseHandle(processInfo.hThread);
        CloseHandle(processInfo.hProcess);
        return 1;
    }

    if (!SendRegisterPid(device, processId))
    {
        std::wcout << L"[KPAM-Client] ERROR: PID registration IOCTL failed. Error code: "
            << GetLastError() << std::endl;
        CloseHandle(device);
        TerminateProcess(processInfo.hProcess, 1);
        CloseHandle(processInfo.hThread);
        CloseHandle(processInfo.hProcess);
        return 1;
    }

    std::wcout << L"[KPAM-Client] PID " << processId
        << L" registered with the driver; starting the inverted-call listener."
        << std::endl;

    OVERLAPPED receiveOverlapped = {};
    receiveOverlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (receiveOverlapped.hEvent == nullptr)
    {
        CloseHandle(device);
        TerminateProcess(processInfo.hProcess, 1);
        CloseHandle(processInfo.hThread);
        CloseHandle(processInfo.hProcess);
        return 1;
    }

    KPAM_EVENT_DATA eventData = {};
    DWORD bytesReturned = 0;
    bool receivePending = false;
    bool targetExited = false;
    ULONGLONG drainDeadline = 0;
    DWORD targetExitCode = STILL_ACTIVE;
    bool fatalReceiveError = false;

    for (;;)
    {
        const ReceiveResult receiveResult = PostReceive(
            device, receiveOverlapped, eventData, bytesReturned);
        if (receiveResult == ReceiveResult::Completed)
        {
            ValidateAndPrintEvent(eventData, bytesReturned);
            continue;
        }
        if (receiveResult == ReceiveResult::Pending)
        {
            receivePending = true;
            break;
        }

        std::wcout << L"[KPAM-Client] ERROR: Failed to start the event IOCTL. Error code: "
            << GetLastError() << std::endl;
        fatalReceiveError = true;
        break;
    }

    if (!fatalReceiveError && ResumeThread(processInfo.hThread) != static_cast<DWORD>(-1))
    {
        std::wcout << L"[KPAM-Client] Resuming target process (PID: "
            << processId << L")." << std::endl;

        while (!fatalReceiveError)
        {
            if (targetExited && GetTickCount64() >= drainDeadline)
            {
                break;
            }

            if (!receivePending)
            {
                const ReceiveResult receiveResult = PostReceive(
                    device, receiveOverlapped, eventData, bytesReturned);
                if (receiveResult == ReceiveResult::Completed)
                {
                    ValidateAndPrintEvent(eventData, bytesReturned);
                    continue;
                }
                if (receiveResult == ReceiveResult::Failed)
                {
                    std::wcout << L"[KPAM-Client] ERROR: Event IOCTL failed. Error code: "
                        << GetLastError() << std::endl;
                    fatalReceiveError = true;
                    break;
                }
                receivePending = true;
            }

            DWORD waitResult;
            if (!targetExited)
            {
                HANDLE waitHandles[] = {
                    processInfo.hProcess,
                    receiveOverlapped.hEvent
                };
                waitResult = WaitForMultipleObjects(2, waitHandles, FALSE, INFINITE);

                if (waitResult == WAIT_OBJECT_0)
                {
                    targetExited = true;
                    drainDeadline = GetTickCount64() + KPAM_DRAIN_TIMEOUT_MS;
                    GetExitCodeProcess(processInfo.hProcess, &targetExitCode);
                    continue;
                }

                if (waitResult != WAIT_OBJECT_0 + 1)
                {
                    fatalReceiveError = true;
                    break;
                }
            }
            else
            {
                const ULONGLONG now = GetTickCount64();
                const DWORD remaining = now >= drainDeadline
                    ? 0
                    : static_cast<DWORD>(drainDeadline - now);
                waitResult = WaitForSingleObject(receiveOverlapped.hEvent, remaining);
                if (waitResult == WAIT_TIMEOUT)
                {
                    break;
                }
                if (waitResult != WAIT_OBJECT_0)
                {
                    fatalReceiveError = true;
                    break;
                }
            }

            if (!GetOverlappedResult(
                device,
                &receiveOverlapped,
                &bytesReturned,
                FALSE))
            {
                const DWORD error = GetLastError();
                receivePending = false;
                if (error != ERROR_OPERATION_ABORTED)
                {
                    std::wcout << L"[KPAM-Client] ERROR: Event IOCTL completion failed. Error code: "
                        << error << std::endl;
                    fatalReceiveError = true;
                }
                continue;
            }

            receivePending = false;
            ValidateAndPrintEvent(eventData, bytesReturned);
        }
    }
    else if (!fatalReceiveError)
    {
        std::wcout << L"[KPAM-Client] ERROR: Failed to resume the target thread. Error code: "
            << GetLastError() << std::endl;
        TerminateProcess(processInfo.hProcess, 1);
        targetExited = true;
        fatalReceiveError = true;
    }

    if (receivePending)
    {
        CancelIoEx(device, &receiveOverlapped);
        WaitForSingleObject(receiveOverlapped.hEvent, INFINITE);
        GetOverlappedResult(device, &receiveOverlapped, &bytesReturned, FALSE);
    }

    if (!targetExited)
    {
        WaitForSingleObject(processInfo.hProcess, INFINITE);
        GetExitCodeProcess(processInfo.hProcess, &targetExitCode);
    }

    std::wcout << L"[KPAM-Client] Target process exited. Exit code: "
        << targetExitCode << std::endl;

    CloseHandle(receiveOverlapped.hEvent);
    CloseHandle(device);
    CloseHandle(processInfo.hThread);
    CloseHandle(processInfo.hProcess);

    return fatalReceiveError ? 1 : 0;
}
