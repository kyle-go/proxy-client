#pragma once
#include <winsock2.h>

bool proxy_socks5(SOCKET s, const char* host, unsigned short port, const char* username=NULL, const char* password=NULL);
