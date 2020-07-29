
#ifdef __cplusplus
extern "C" {
#endif

#ifndef WEI_HTTPC_CONNECT_H
#define WEI_HTTPC_CONNECT_H

#ifndef IN
#define IN
#endif

#ifndef OUT
#define OUT	
#endif

#ifndef PRIVATE
#define PRIVATE
#endif

#ifndef PUBLIC
#define PUBLIC
#endif

#ifndef NULL
#define NULL 0
#endif

#ifndef UINT
#define UINT unsigned int
#endif

//
//#define bool int
//#define false 0
//#define true 1

//PUBLIC bool wei_set_proxy_info(char * proxy_ip,UINT proxy_port,char * host,char * domain,char * user, char * passwd);
//PUBLIC void wei_reset_proxy_info();
//PUBLIC bool wei_is_httppc_connected();
//int wei_httppc_connect(char * remote_ip ,int remote_port);

bool is_ntlm_proxy_supported(const char* remote_ip, unsigned short remote_port);
// 返回0表示成功，其他表示失败
bool ntlm_proxy_connected(int s, const char* lpszHost, UINT nPort, const char* proxy_ip, unsigned short proxy_port, const char* user, const char* password);
#endif

#ifdef __cplusplus
}
#endif
