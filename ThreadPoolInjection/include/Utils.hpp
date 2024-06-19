#pragma once
#include <Windows.h>
#include <iostream>
#include <string>
#include <Psapi.h>
#include "functionPtrs.hpp"
#include "defs.hpp"

HANDLE hijackProcessWorkerFactory(HANDLE processHandle);
HANDLE hijackProcessTimerQueue(HANDLE processHandle);
HANDLE hijackProcessIoPort(HANDLE processHandle);
HANDLE hijackProcessHandle(_In_ HANDLE targetProcess, _In_ const wchar_t* handleTypeName, _In_ uint32_t desiredAccess);
HANDLE enumerateProcess(_In_ wchar_t* processName, _Outptr_opt_ uint32_t* pPid);
bool writePayloadIntoProcess(_In_ HANDLE hProcess, _In_ void* pPayload, _In_ size_t payloadSize, _Out_ void** pRemoteAddress);