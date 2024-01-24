#pragma once
#include <Windows.h>


bool InjectViaJobCallback(_In_ HANDLE targetProcess, _In_ void* payloadAddress, _In_ HANDLE hIoPort);