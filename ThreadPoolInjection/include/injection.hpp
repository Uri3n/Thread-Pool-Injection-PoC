#pragma once
#include <Windows.h>
#include <iostream>
#include <stdint.h>
#include "functionPtrs.hpp"
#include "structures.hpp"
#include "defs.hpp"



//IO
bool InjectViaJobCallback(_In_ HANDLE targetProcess, _In_ void* payloadAddress, _In_ HANDLE hIoPort);
bool InjectViaTpWait(_In_ HANDLE targetProcess, _In_ void* payloadAddress, _In_ HANDLE hIoPort);
bool InjectViaTpIo(_In_ HANDLE targetProcess, _In_ void* payloadAddress, _In_ HANDLE hIoPort);
bool InjectViaAlpc(_In_ HANDLE targetProcess, _In_ void* payloadAddress, _In_ HANDLE hIoPort);
bool InjectViaTpDirect(_In_ HANDLE targetProcess, _In_ void* payloadAddress, _In_ HANDLE hIoPort);

//TIMER
bool InjectViaTpTimer(_In_ HANDLE hWorkerFactory, _In_ HANDLE hTimer, _In_ void* payloadAddress, _In_ HANDLE targetProcess);

//WORKER FACTORY / TP_WORK
bool InjectViaWorkerFactoryStartRoutine(_In_ HANDLE targetProcess, _In_ HANDLE hWorkerFactory, _In_ void* localPayloadAddress, _In_ size_t payloadSize);
bool InjectViaTpWork(_In_ HANDLE targetProcess, _In_ void* payloadAddress, _In_ HANDLE hWorkerFactory);
