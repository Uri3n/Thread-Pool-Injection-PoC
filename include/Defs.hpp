#pragma once

#define MY_MESSAGE "I did it for the vine."
#define WIN32_ERR(API) std::cout << "{!!} " << #API << " failed with error: " << GetLastError() << std::endl;
#define NTAPI_ERR(API, status) std::cout << "{!!} " << #API << " failed with status: " << std::hex << status << std::endl;

// Worker Factory
#define WORKER_FACTORY_RELEASE_WORKER 0x0001
#define WORKER_FACTORY_WAIT 0x0002
#define WORKER_FACTORY_SET_INFORMATION 0x0004
#define WORKER_FACTORY_QUERY_INFORMATION 0x0008
#define WORKER_FACTORY_READY_WORKER 0x0010
#define WORKER_FACTORY_SHUTDOWN 0x0020

#define WORKER_FACTORY_ALL_ACCESS ( \
       STANDARD_RIGHTS_REQUIRED | \
       WORKER_FACTORY_RELEASE_WORKER | \
       WORKER_FACTORY_WAIT | \
       WORKER_FACTORY_SET_INFORMATION | \
       WORKER_FACTORY_QUERY_INFORMATION | \
       WORKER_FACTORY_READY_WORKER | \
       WORKER_FACTORY_SHUTDOWN \
)

// IO
#define IO_COMPLETION_MODIFY_STATE  0x0002  
#define IO_COMPLETION_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|0x3) 

#define IO_QOS_MAX_RESERVATION 1000000000ULL


// Timer
#define TIMER_QUERY_STATE       0x0001
#define TIMER_MODIFY_STATE      0x0002

#define TIMER_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|\
                          TIMER_QUERY_STATE|TIMER_MODIFY_STATE)

enum HandleHijackClass {
    TpIoPort,
    TpWorkerFactory,
    TpTimer
};


