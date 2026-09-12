# KPAM

KPAM is an experimental Windows kernel telemetry project. It monitors selected process activity in kernel mode and streams structured events to a user-mode client through an inverted-call model.

The client starts a target executable in a suspended state, registers its process ID with the driver, posts an asynchronous event request, and then resumes the process. Telemetry received by the client is printed in the same format as the driver's `DbgPrint` output so both streams can be compared directly.

## Telemetry

KPAM currently reports:

- Process creation and termination
- Thread creation and termination
- Registry value writes and key creation
- Image and DLL loads
- Process and thread handle requests
- File open operations
- IPv4 and IPv6 connection attempts

Only processes registered with the driver, along with child processes added by the process monitor, are tracked.

## Repository layout

```text
KPAM.sln
Client/                 User-mode telemetry client
KPAM/                   Kernel driver
KPAM/include/           Shared driver and client protocol
KPAM/Telemetry/         Telemetry callback implementations
```

## Requirements

- Windows 10 or Windows 11 x64
- Visual Studio 2022 with Desktop development with C++
- Windows Driver Kit compatible with the installed Windows SDK
- Administrator access to deploy and start the driver
- A dedicated test machine or virtual machine configured for test-signed drivers

## Build

Open `KPAM.sln` in Visual Studio and build the `Debug | x64` or `Release | x64` configuration.

The solution produces:

- `KPAM.sys`, the kernel driver
- `Client.exe`, the user-mode event consumer

Generated binaries, symbols, certificates, catalogs, and Visual Studio state are intentionally excluded from version control.

## Usage

Deploy and start the newly built driver in your test environment, then run:

```powershell
Client.exe <target_executable_path>
```

Example:

```powershell
Client.exe C:\Samples\sample.exe
```

The client remains connected while the target runs and continuously posts `IOCTL_KPAM_GET_NEXT_EVENT` requests. When the target exits, the client briefly drains queued events, cancels the final pending request, and closes the device handle.

## Safety

This project contains kernel-mode code. A defect can crash or destabilize Windows. Build and run it only in an isolated development environment or virtual machine. Do not use it to inspect systems or processes without authorization.
