#pragma once
#include "KpamData.h"

extern LARGE_INTEGER g_RegCookie;

NTSTATUS KpamRegistryCallback(
    PVOID CallbackContext,
    PVOID Argument1,
    PVOID Argument2
);
