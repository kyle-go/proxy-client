#include "socks5.h"

#pragma pack(push)
#pragma pack(1)
struct socks5req1
{
	char Ver;
	char nMethods;
	char Methods[2];
};

struct socks5ans1
{
	char Ver;
	char Method;
};

struct socks5req2
{
	char Ver;
	char Cmd;
	char Rsv;
	char Atyp;
	unsigned long IPAddr;
	unsigned short Port;
};

struct socks5ans2
{
	char Ver;
	char Rep;
	char Rsv;
	char Atyp;
	char other[1];
};
#pragma pack(pop)

bool proxy_socks5(SOCKET s, const char* host, unsigned short port, const char* username, const char* password) {
	// use user/password
	bool bUserPass = true;
	if (username == NULL || strlen(username) == 0) {
		bUserPass = false;
	}

	struct timeval tvSelect_Time_Out;
	tvSelect_Time_Out.tv_sec = 3;
	tvSelect_Time_Out.tv_usec = 0;
	fd_set fdRead;
	int	nRet = SOCKET_ERROR;

	struct socks5req1 m_proxyreq1;
	m_proxyreq1.Ver = 5;

	if (bUserPass) {
		m_proxyreq1.nMethods = 2;
		m_proxyreq1.Methods[0] = 0;
		m_proxyreq1.Methods[1] = 2;
		send(s, (char*)&m_proxyreq1, 4, 0);
	}
	else {
		m_proxyreq1.nMethods = 1;
		m_proxyreq1.Methods[0] = 0;
		send(s, (char*)&m_proxyreq1, 3, 0);
	}
	char buff[512] = { 0 };
	struct socks5ans1* m_proxyans1 = (struct socks5ans1*)buff;

	FD_ZERO(&fdRead);
	FD_SET(s, &fdRead);
	nRet = select(0, &fdRead, NULL, NULL, &tvSelect_Time_Out);
	if (nRet <= 0)
	{
		return false;
	}
	recv(s, buff, sizeof(buff), 0);
	if (m_proxyans1->Ver != 5 || (m_proxyans1->Method != 0 && m_proxyans1->Method != 2))
	{
		return false;
	}

	// 需要密码认证
	if (m_proxyans1->Method == 2)
	{
		if (!bUserPass) {
			return false;
		}
		memset(buff, 0, sizeof(buff));
		buff[0] = 1;
		buff[1] = strlen(username);
		memcpy(buff + 2, username, strlen(username));
		buff[2 + strlen(username)] = strlen(password);
		memcpy(buff + 2 + strlen(username) + 1, password, strlen(password));
		send(s, (char*)buff, 3 + strlen(username) + strlen(password), 0);

		FD_ZERO(&fdRead);
		FD_SET(s, &fdRead);
		nRet = select(0, &fdRead, NULL, NULL, &tvSelect_Time_Out);
		if (nRet <= 0) {
			return false;
		}
		nRet = recv(s, buff, sizeof(buff), 0);
		if (nRet == 2 && buff[0] == 1 && buff[1] == 0) {
			// success
		}
		else {
			return false;
		}
	}

	// 无需密码认证，直接到这里
	hostent* pHostent = gethostbyname(host);
	if (pHostent == NULL)
		return false;

	struct socks5req2 m_proxyreq2;
	m_proxyreq2.Ver = 5;
	m_proxyreq2.Cmd = 1;
	m_proxyreq2.Rsv = 0;
	m_proxyreq2.Atyp = 1;
	m_proxyreq2.IPAddr = *(ULONG*)pHostent->h_addr_list[0];
	m_proxyreq2.Port = ntohs(port);

	send(s, (char*)&m_proxyreq2, 10, 0);
	struct socks5ans2* m_proxyans2 = (struct socks5ans2*)buff;
	memset(buff, 0, sizeof(buff));

	FD_ZERO(&fdRead);
	FD_SET(s, &fdRead);
	nRet = select(0, &fdRead, NULL, NULL, &tvSelect_Time_Out);
	if (nRet <= 0) {
		return false;
	}

	recv(s, buff, sizeof(buff), 0);
	if (m_proxyans2->Ver != 5 || m_proxyans2->Rep != 0)
	{
		return false;
	}
	return true;
}
