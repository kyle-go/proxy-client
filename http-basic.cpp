#include "http-basic.h"
#include "base64.h"
#include "stdio.h"

bool proxy_http_basic(SOCKET s, const char* host, unsigned short port, const char* username, const char* password) {
	char buff[1024] = { 0 };
	// use user/password or not
	if (username == NULL || strlen(username) == 0) {
		sprintf(buff, "CONNECT %s:%d HTTP/1.1\r\n\r\n", host, port);
	}
	else {
		std::string upstr = username + std::string(":") + password;
		std::string base64Str = common::base64::encode(upstr);
		sprintf(buff, "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\nProxy-Authorization: Basic %s\r\n\r\n",
			host, port, host, port, base64Str.c_str());
	}
	send(s, buff, strlen(buff), 0);

	ZeroMemory(buff, sizeof(buff));
	int nSize = recv(s, buff, sizeof(buff), 0);
	if (nSize <= 0)
	{
		return false;
	}

	// find "200" in "HTTP/1.1 200 Connection established"
	if (strstr(buff, "200")) {
		return true;
	}
	return false;
}
