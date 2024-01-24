#pragma once
#include <Windows.h>
#include <winternl.h>
#include "structures.hpp"

typedef NTSTATUS(NTAPI* fnNtQueryInformationProcess)(

    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

typedef NTSTATUS(NTAPI* fnTpAllocJobNotification)(

    _Out_ PFULL_TP_JOB* JobReturn,
    _In_ HANDLE HJob,
    _In_ PVOID Callback,
    _Inout_opt_ PVOID Context,
    _In_opt_ PTP_CALLBACK_ENVIRON CallbackEnviron
    );

typedef NTSTATUS(NTAPI* fnNtQueryObject)(

    _In_opt_ HANDLE Handle,
    _In_ OBJECT_INFORMATION_CLASS ObjectInformationClass,
    _Out_writes_bytes_opt_(ObjectInformationLength) PVOID ObjectInformation,
    _In_ ULONG ObjectInformationLength,
    _Out_opt_ PULONG ReturnLength
);

typedef NTSTATUS(NTAPI* fnRtlAdjustPrivilege)(

    _In_ ULONG Privilege,
    _In_ BOOLEAN Enable,
    _In_ BOOLEAN Client,
    _Out_ PBOOLEAN WasEnabled
    );

typedef NTSTATUS(NTAPI* fnNtQuerySystemInformation)(

    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID                    SystemInformation,
    ULONG                    SystemInformationLength,
    PULONG                   ReturnLength
    );

typedef NTSTATUS(NTAPI* fnNtAssociateWaitCompletionPacket)(

    _In_ HANDLE WaitCompletionPacketHandle,
    _In_ HANDLE IoCompletionHandle,
    _In_ HANDLE TargetObjectHandle,
    _In_opt_ PVOID KeyContext,
    _In_opt_ PVOID ApcContext,
    _In_ NTSTATUS IoStatus,
    _In_ ULONG_PTR IoStatusInformation,
    _Out_opt_ PBOOLEAN AlreadySignaled
);

typedef NTSTATUS(NTAPI* fnNtSetInformationFile)(

    _In_ HANDLE FileHandle,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_reads_bytes_(Length) PVOID FileInformation,
    _In_ ULONG Length,
    _In_ FILE_INFORMATION_CLASS FileInformationClass
);

typedef NTSTATUS(NTAPI* fnNtAlpcCreatePort)(

    _Out_ PHANDLE PortHandle,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PALPC_PORT_ATTRIBUTES PortAttributes
);

typedef NTSTATUS(NTAPI* fnTpAllocAlpcCompletion)(

    _Out_ PFULL_TP_ALPC* AlpcReturn,
    _In_ HANDLE AlpcPort,
    _In_ PTP_ALPC_CALLBACK Callback,
    _Inout_opt_ PVOID Context,
    _In_opt_ PTP_CALLBACK_ENVIRON CallbackEnviron
);

typedef NTSTATUS(NTAPI* fnRtlInitUnicodeString)(

    _In_ PUNICODE_STRING DestinationString,
    _In_ PCWSTR SourceString
);

typedef NTSTATUS(NTAPI* fnNtAlpcSetInformation)(

    _In_ HANDLE PortHandle,
    _In_ ULONG PortInformationClass,
    _In_reads_bytes_opt_(Length) PVOID PortInformation,
    _In_ ULONG Length
);

typedef NTSTATUS(NTAPI* fnNtAlpcConnectPort)(

    _Out_ PHANDLE PortHandle,
    _In_ PUNICODE_STRING PortName,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PALPC_PORT_ATTRIBUTES PortAttributes,
    _In_ DWORD ConnectionFlags,
    _In_opt_ PSID RequiredServerSid,
    _In_opt_ PPORT_MESSAGE ConnectionMessage,
    _Inout_opt_ PSIZE_T ConnectMessageSize,
    _In_opt_ PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes,
    _In_opt_ PALPC_MESSAGE_ATTRIBUTES InMessageAttributes,
    _In_opt_ PLARGE_INTEGER Timeout
);

typedef NTSTATUS(NTAPI* fnNtSetIoCompletion)(

    _In_ HANDLE IoCompletionHandle,
    _In_opt_ PVOID KeyContext,
    _In_opt_ PVOID ApcContext,
    _In_ NTSTATUS IoStatus,
    _In_ ULONG_PTR IoStatusInformation
);

typedef NTSTATUS(NTAPI* fnNtQueryInformationWorkerFactory)(

    _In_ HANDLE WorkerFactoryHandle,
    _In_ QUERY_WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
    _Out_writes_bytes_(WorkerFactoryInformationLength) PVOID WorkerFactoryInformation,
    _In_ ULONG WorkerFactoryInformationLength,
    _Out_opt_ PULONG ReturnLength
);

typedef NTSTATUS(NTAPI* fnNtSetTimer2)(

    _In_ HANDLE TimerHandle,
    _In_ PLARGE_INTEGER DueTime,
    _In_opt_ PLARGE_INTEGER Period,
    _In_ PT2_SET_PARAMETERS Parameters
);

typedef NTSTATUS(NTAPI* fnNtSetInformationWorkerFactory)(

    _In_ HANDLE WorkerFactoryHandle,
    _In_ SET_WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
    _In_reads_bytes_(WorkerFactoryInformationLength) PVOID WorkerFactoryInformation,
    _In_ ULONG WorkerFactoryInformationLength
);