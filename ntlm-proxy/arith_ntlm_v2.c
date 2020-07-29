/****************************************************************************************
 *                                                                                      *
 * 本源代码用于HTTP PROXY的NTLM算法中使用的NTLM v2算法。                                *
 *                                                                                      *
 ****************************************************************************************/
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdarg.h>
#include <stdio.h>
#include "arithmetic.h"


/*********************************** NTLM-v2 算法 begin ********************************/
static void ntlmv2_unicode(IN char * user_name, IN char * domain,
						   OUT char * user){
	char * temp;
	int len1 = strlen(user_name);
	int len2 = strlen(domain);

	temp = ( char *) malloc(len1 + len2 + 1);
	strcpy(temp,user_name);
	strcat(temp,domain);
	strtoupper(temp);
	unicode(temp,len1 + len2,user,NULL);
	free(temp);
}

void ntlmv2_response(IN char * passwd, IN char * user_name,IN char * domain,
					 IN unsigned char * chanllenge, IN unsigned char * target_info,
					 IN int target_info_len,IN unsigned char * client_nonce,
					 OUT unsigned char * ntlm_response, OUT int * ntlm_response_len,
					 OUT unsigned char * lm_response,   OUT int * lm_response_len){
	unsigned char hash[16],digest[16];
	unsigned char * name;
	int len ;
	long cur_time = 0;
	long long  t;
	
	//v2-Hash = HMAC-MD5(NT-Hash, user name, domain name)
	//结果放置在hash中，中途使用digest进行数据存贮，后无用
	nt_hash(passwd, 0,digest,NULL);
	len = (strlen(user_name) + strlen(domain)) * 2;
	name = (unsigned char *) malloc(len);
	ntlmv2_unicode(user_name,domain,(char *)name);
	HMAC_MD5(name, len, digest,16,hash);
	free(name);

	//CC* = (X, time, CC, domain name)
	//Next, the blob is constructed. The timestamp is the most tedious part of this
	//Adding 11644473600 will give us seconds after January 1, 1601 
	//Multiplying by 107 (10000000) will give us tenths of a microsecond
	len = 40 + target_info_len ;
	name = (unsigned char *)malloc(len);
	memset(name,0,len);
	memcpy(name,chanllenge,8);
	name[8] = 0x01;
	name[9] = 0x01;
	cur_time = (long)time(NULL);

	//cur_time = 1055844000;
	t = (cur_time + 11644473600) * 10000000;
	memcpy(name + 16, &t , 8);
	memcpy(name + 24,client_nonce,8);
	memcpy(name + 36,target_info,target_info_len);

	//NTv2 = HMAC-MD5(v2-Hash, CS, CC*)
	HMAC_MD5(name, len, hash,16,ntlm_response);
	memcpy(ntlm_response + 16,name + 8,len - 8);
	if(ntlm_response_len != NULL)
		* ntlm_response_len = len + 8;
	free(name);


	//LMv2 = HMAC-MD5(v2-Hash, CS, CC)
	name = (unsigned char *) malloc(16);
	memcpy(name,chanllenge,8);
	memcpy(name + 8,client_nonce,8);
	HMAC_MD5(name, 16, hash,16,lm_response);
	memcpy(lm_response + 16,client_nonce,8);
	if(lm_response_len != NULL)
		* lm_response_len = 24;
	free(name);
}
