/****************************************************************************************
 *                                                                                      *
 * 本源代码用于HTTP PROXY的NTLM算法中使用的NTLM v1算法。                                *
 *                                                                                      *
 ****************************************************************************************/

#include <string.h>
#include <stdlib.h>
#include "arithmetic.h"

/*********************************** NTLM-v1 算法 begin ********************************/
void ntlmv1_response(IN char * passwd, IN unsigned char * chanllenge,
					 OUT unsigned char * ntlm_response,OUT int * ntlm_response_len,
					 OUT unsigned char * lm_response, OUT int * lm_response_len){
					 //OUT unsigned char * dst, OUT int * dst_len){
	unsigned char hash[21];

	//K1 | K2 | K3 = LM-Hash | 5-bytes-0
	//R1 = DES(K1,C) | DES(K2,C) | DES(K3,C)
	lm_hash(passwd, hash,NULL);
	memset(hash + 16,0,5);
	/*
	algorithm_des_56key(chanllenge, hash,dst);
	algorithm_des_56key(chanllenge, hash+7,dst+8);
	algorithm_des_56key(chanllenge, hash+14,dst+16);
	*/
	algorithm_des_56key(chanllenge, hash,lm_response);
	algorithm_des_56key(chanllenge, hash+7,lm_response+8);
	algorithm_des_56key(chanllenge, hash+14,lm_response+16);
	if(lm_response_len != NULL)
		* lm_response_len = 24;

	//K1 | K2 | K3 = NT-Hash | 5-bytes-0
	//R2 = DES(K1,C) | DES(K2,C) | DES(K3,C)
	nt_hash(passwd, 0,hash,NULL);
	memset(hash + 16,0,5);
	/*algorithm_des_56key(chanllenge,hash,dst+24);
	algorithm_des_56key(chanllenge,hash+7,dst+32);
	algorithm_des_56key(chanllenge,hash+14,dst+40);*/
	algorithm_des_56key(chanllenge,hash,ntlm_response);
	algorithm_des_56key(chanllenge,hash+7,ntlm_response+8);
	algorithm_des_56key(chanllenge,hash+14,ntlm_response+16);
	if(ntlm_response_len != NULL)
		* ntlm_response_len = 24;
/*
	if(dst_len != NULL)
		* dst_len = 48;*/
}
