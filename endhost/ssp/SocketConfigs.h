#ifndef SCION_GENERAL_CONFIG_H
#define SCION_GENERAL_CONFIG_H

// Build config

//#define SIMULATOR // uncomment for WANem testing
//#define BYPASS_ROUTERS // send packets directly to remote end

#define DEBUG_MODE 0
#if DEBUG_MODE
#define DEBUG printf
#else
#define DEBUG(...)
#endif

#define MAX_PATH_LEN 231
#define MAX_USED_PATHS 2
#define MAX_DATA_PACKET 65535

#define SCION_DEFAULT_MTU 1500

// time values in us
#define SCION_TIMER_INTERVAL 50000
#define SCION_DEFAULT_RTO 3000000
#define SCION_DEFAULT_RTT 1000000

#define SCION_SELECT_READ 0
#define SCION_SELECT_WRITE 1

#endif
