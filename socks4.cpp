#include "socks4.h"

#pragma pack(push)
#pragma pack(1)
struct socks4req1
{
	char Ver;
	char cd;
	unsigned short port;
	unsigned long IPAddr;
	unsigned char reserved;
};
#pragma pack(pop)

bool proxy_socks4(SOCKET s, const char* host, unsigned short port) {
	struct timeval tvSelect_Time_Out;
	tvSelect_Time_Out.tv_sec = 3;
	tvSelect_Time_Out.tv_usec = 0;
	fd_set fdRead;
	int	nRet = SOCKET_ERROR;

	hostent* pHostent = gethostbyname(host);
	if (pHostent == NULL)
		return false;

	struct socks4req1 m_proxyreq1;
	m_proxyreq1.Ver = 4;
	m_proxyreq1.cd = 0x01; // CONNECT
	m_proxyreq1.port = ntohs(port);
	m_proxyreq1.IPAddr = *(ULONG*)pHostent->h_addr_list[0];
	m_proxyreq1.reserved = 0;
	send(s, (char*)&m_proxyreq1, sizeof(socks4req1), 0);

	FD_ZERO(&fdRead);
	FD_SET(s, &fdRead);
	nRet = select(0, &fdRead, NULL, NULL, &tvSelect_Time_Out);
	if (nRet <= 0)
	{
		return false;
	}

	char buff[512] = { 0 };
	nRet = recv(s, buff, sizeof(buff), 0);
	if (buff[1] == 0x5A) {
		return true;
	}
	return false;
}
