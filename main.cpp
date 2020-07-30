// proxy server http://www.ccproxy.com/download.htm
//

#include <stdio.h>
#include <winsock2.h>
#include "socks4.h"
#include "socks4a.h"
#include "socks5.h"
#include "http-basic.h"
#include "ntlm-proxy/ntlm_proxy.h"

#pragma comment(lib, "ws2_32.lib")

#define PROXY_IP "192.168.0.168"

#define TEST_HOST_DOMAIN "biying.com"
#define TEST_HOST_PORT 80


SOCKET connect_proxy_server(const char* proxy_ip, unsigned short proxy_port) {
	SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == INVALID_SOCKET) {
		printf("socket function failed with error: %d\n", GetLastError());
		return INVALID_SOCKET;
	}

	hostent* pHostent = gethostbyname(proxy_ip);
	if (pHostent == NULL) {
		printf("gethostbyname function failed with error: %d\n", GetLastError());
		return INVALID_SOCKET;
	}

	struct sockaddr_in servaddr = { 0 };
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(proxy_port);
	servaddr.sin_addr = *((struct in_addr *)pHostent->h_addr);

	if (connect(sock, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
		printf("connect function failed with error: %d\n", GetLastError());
		return INVALID_SOCKET;
	}
	return sock;
}

bool http_request(SOCKET sock) {
	char buf[1024] = { 0 };
	sprintf(buf, "GET %s:%d HTTP/1.1 \r\n\r\n", TEST_HOST_DOMAIN, TEST_HOST_PORT);
	send(sock, buf, strlen(buf), 0);

	struct timeval tvSelect_Time_Out;
	tvSelect_Time_Out.tv_sec = 3;
	tvSelect_Time_Out.tv_usec = 0;
	fd_set fdRead;
	FD_ZERO(&fdRead);
	FD_SET(sock, &fdRead);
	int nRet = select(0, &fdRead, NULL, NULL, &tvSelect_Time_Out);
	if (nRet <= 0)
	{
		return false;
	}

	ZeroMemory(buf, sizeof(buf));
	nRet = recv(sock, buf, sizeof(buf), 0);
	if (nRet > 0) {
		printf("HTTP Request Recv:%s\r\n", buf);
		return true;
	}
	return false;
}

int main()
{
	WSADATA wsaData;
	int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != NO_ERROR) {
		printf("WSAStartup function failed with error: %d\n", iResult);
		return -1;
	}

	// ***** socks4 proxy *************
	{
		printf("****** testing proxy_socks4.\n");
		SOCKET sock = connect_proxy_server(PROXY_IP, 1080);
		if (sock != INVALID_SOCKET) {
			if (proxy_socks4(sock, TEST_HOST_DOMAIN, TEST_HOST_PORT)) {
				printf("proxy_socks4 connect ok.\n");
				if (http_request(sock)) {
					printf("proxy_socks4 http_request OK.\n");
				}
				else {
					printf("proxy_socks4 http_request failed.\n");
				}
			}
			else {
				printf("proxy_socks4 failed.\n");
			}
			closesocket(sock);
		}
		else {
			printf("connect_proxy_server failed.\n");
		}
	}

	// ***** sock4A
	{
		printf("****** testing proxy_socks4A.\n");
		SOCKET sock = connect_proxy_server(PROXY_IP, 1080);
		if (sock != INVALID_SOCKET) {
			if (proxy_socks4a(sock, TEST_HOST_DOMAIN, TEST_HOST_PORT)) {
				printf("proxy_socks4A connect ok.\n");
				if (http_request(sock)) {
					printf("proxy_socks4A http_request OK.\n");
				}
				else {
					printf("proxy_socks4A http_request failed.\n");
				}
			}
			else {
				printf("proxy_socks4A failed.\n");
			}
			closesocket(sock);
		}
		else {
			printf("connect_proxy_server failed.\n");
		}
	}

	// sock5
	{
		printf("****** testing proxy_socks5.\n");
		SOCKET sock = connect_proxy_server(PROXY_IP, 1080);
		if (sock != INVALID_SOCKET) {
			if (proxy_socks5(sock, TEST_HOST_DOMAIN, TEST_HOST_PORT, "test", "123456")) {
				printf("proxy_socks5 connect ok.\n");
				if (http_request(sock)) {
					printf("proxy_socks5 http_request OK.\n");
				}
				else {
					printf("proxy_socks5 http_request failed.\n");
				}
			}
			else {
				printf("proxy_socks5 failed.\n");
			}
			closesocket(sock);
		}
		else {
			printf("connect_proxy_server failed.\n");
		}
	}

	// http basic
	{
		printf("****** testing proxy_http_basic.\n");
		SOCKET sock = connect_proxy_server(PROXY_IP, 808);
		if (sock != INVALID_SOCKET) {
			if (proxy_http_basic(sock, TEST_HOST_DOMAIN, TEST_HOST_PORT, "test", "123456")) {
				printf("proxy_http_basic connect ok.\n");
				if (http_request(sock)) {
					printf("proxy_http_basic http_request OK.\n");
				}
				else {
					printf("proxy_http_basic http_request failed.\n");
				}
			}
			else {
				printf("proxy_http_basic failed.\n");
			}
			closesocket(sock);
		}
		else {
			printf("connect_proxy_server failed.\n");
		}
	}

	// http ntlm
	{
		printf("****** testing proxy_http_ntlm.\n");
		SOCKET sock = connect_proxy_server(PROXY_IP, 808);
		if (sock != INVALID_SOCKET) {
			if (is_ntlm_proxy_supported(PROXY_IP, 808)) {
				if (ntlm_proxy_connected(sock, TEST_HOST_DOMAIN, TEST_HOST_PORT, PROXY_IP, 808, "test", "123456")) {
					printf("proxy_http_ntlm connect ok.\n");
					if (http_request(sock)) {
						printf("proxy_http_ntlm http_request OK.\n");
					}
					else {
						printf("proxy_http_ntlm http_request failed.\n");
					}
				}
				else {
					printf("proxy_http_ntlm failed.\n");
				}
			}
			else {
				printf("proxy_http_ntlm NOT SUPPORTED.\n");
			}
			closesocket(sock);
		}
		else {
			printf("connect_proxy_server failed.\n");
		}
	}

	WSACleanup();
	return 0;
}
