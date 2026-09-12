#pragma once

#include "KpamData.h"

NTSTATUS KpamRegisterNetworkCallout(PDEVICE_OBJECT DeviceObject);

void KpamUnregisterNetworkCallout();
