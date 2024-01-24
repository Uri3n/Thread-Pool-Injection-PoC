#pragma once
#include <Windows.h>
#include <iostream>
#include <stdint.h>
#include "functionPtrs.hpp"
#include "structures.hpp"
#define WIN32_ERR(API) std::cout << "{!!} " << #API << " failed with error: " << GetLastError() << std::endl;
#define NTAPI_ERR(API, status) std::cout << "{!!} " << #API << " failed with status: " << std::hex << status << std::endl;

