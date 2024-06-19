#pragma once
#include <Windows.h>
#include <cstdint>
#include "defs.hpp"
#include "injection.hpp"
#include "Utils.hpp"


class Process {

private:

	wchar_t*          name           = nullptr;
	void*             remotePayload  = nullptr;
	HANDLE            handleToHijack = nullptr;
	HANDLE            processHandle  = nullptr;
	bool              isInitialized  = false;
	uint32_t          PID            = 0;

	HandleHijackClass hijackType;

public:

	bool injectShellcode();
	bool ProcessAlpcInject();
	bool ProcessJobInject();
	bool ProcessWaitInject();
	bool ProcessTpIoInject();
	bool ProcessTpDirectInject();
	bool ProcessTimerInject();
	bool ProcessWorkInject();
	bool ProcessWorkerFactoryInject();
	bool init();


	~Process();
	Process(wchar_t* processName, HandleHijackClass hijackType) : name(processName), hijackType(hijackType) {}
};