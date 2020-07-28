#pragma once
#include <winsock2.h>

bool proxy_http_basic(SOCKET s, const char* host, unsigned short port, const char* username = NULL, const char* password = NULL);
