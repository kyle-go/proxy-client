#ifdef __cplusplus
extern "C" {
#endif

#ifndef WEI_HTTPC_NTLM_H
#define WEI_HTTPC_NTLM_H

#ifndef byte
#define byte unsigned char
#endif

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

#define AUTHOR_NTLM_1			1
#define AUTHOR_NTLM_2			2
#define AUTHOR_NTLM_SESSION		3

//#define bool int
//#define false 0
//#define true 1

//用于处理NTLM的Proxy算法
typedef struct ges_ntlm_type_1_message{
	char			protocol[8];     // 'N', 'T', 'L', 'M', 'S', 'S', 'P', '\0'
	unsigned int	type;            // 0x01
//	byte			zero_1[3];
	
	unsigned int	flags;           // old:0xb203 new : 0xa208b207

	short			dom_len1;        // domain string length
	short			dom_len2;        // domain string length
	unsigned int	dom_off;
	//short			dom_off;         // domain string offset
	//byte			zero_3[2];

	short			host_len1;       // host string length
	short			host_len2;       // host string length
	unsigned int	host_off;        // host string offset (always 0x20)
	//byte			zero_4[2];
	
	char            * os_version;	// Options 8字节的OS version 信息，但是我们不使用
	char			* host;         // host string (ASCII)
	char			* dom;          // domain string (ASCII)
} T_NTLM_TYPE_1_MSG;



typedef struct ges_ntlm_type_2_message{
	char			protocol[8];     // 'N', 'T', 'L', 'M', 'S', 'S', 'P', '\0'
	unsigned int	type;
	short			target_name_len;
	short			target_name_allocation;
	unsigned int	target_name_offset;
	int				flags;           // 0x8201，有0x02008201
	byte			nonce[8];        // nonce or challenge
	byte			context[8];
	short			target_info_len;
	short			target_info_alloction;
	unsigned int	target_info_offset;
	byte *			target_name;
	byte *			target_info;
}T_NTLM_TYPE_2_MSG;


typedef struct ges_ntlm_type_3_message{
	byte			protocol[8];     // 'N', 'T', 'L', 'M', 'S', 'S', 'P', '\0'
	unsigned int	type;

	short			lm_resp_len;     // LanManager response length (always 0x18)
	short			lm_resp_allocation;     // LanManager response length (always 0x18)
	unsigned int    lm_resp_offset;     // LanManager response offset

	short			nt_resp_len;     // NT response length (always 0x18)
	short			nt_resp_allocation;     // NT response length (always 0x18)
	unsigned int    nt_resp_offset;     // NT response offset

	short			domain_len;
	short			domain_allocation;
	unsigned int	domain_offset;

	short			user_len;        // username string length
	short			user_allocation;        // username string length
	unsigned int    user_offset;        // username string offset

	short			host_len;        // host string length
	short			host_allocation;        // host string length
	unsigned int	host_offset;        // host string offset

	unsigned int	zero;
	unsigned int	msg_len;

	unsigned int    flags;           // 0x8201

	char			* domain;          // domain string (unicode UTF-16LE)
	char			* user;         // username string (unicode UTF-16LE)
	char			* host;         // host string (unicode UTF-16LE)
	byte			* lm_resp;      // LanManager response
	byte			* nt_resp;      // NT response
}T_NTLM_TYPE_3_MSG;

//获取NTLM的type_1_message的值
void wei_ntlm_make_type1_base64(IN bool is_little_endian,IN char * domain,IN char * host_name,
								IN int author_type,OUT char * buf);
bool wei_ntlm_decode_type2(IN bool is_little_endian,IN char * info, OUT T_NTLM_TYPE_2_MSG * type);
bool wei_ntlm_make_type3_base64(IN bool is_little_endian,IN char * domain ,IN char * host, IN char * user,
								IN char * passwd, IN T_NTLM_TYPE_2_MSG * type2_msg, OUT char * buf);
#endif

#ifdef __cplusplus
}
#endif
