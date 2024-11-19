#pragma once
#include <Windows.h>
#include <cstdint>
#include "Defs.hpp"
#include "Injection.hpp"
#include "Utils.hpp"

class Process {
private:
	void*    remotePayload  = nullptr;
	HANDLE   handleToHijack = nullptr;
	HANDLE   processHandle  = nullptr;
	bool     isInitialized  = false;
	uint32_t PID            = 0;

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
	Process(uint32_t _PID, HandleHijackClass hijackType)
		: PID(_PID), hijackType(hijackType) {}
};