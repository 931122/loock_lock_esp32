#pragma once
#include <stdbool.h>

#define NET_LOG_PORT 8888

void net_log_init(void);
void net_log_start(const char *local_ip);
void net_log_stop(void);
