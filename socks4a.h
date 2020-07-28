#pragma once
#include <winsock2.h>

bool proxy_socks4a(SOCKET s, const char* host, unsigned short port);
