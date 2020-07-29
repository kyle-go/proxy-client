/****************************************************************************************
 *                                                                                      *
 * 本源代码用于HTTP PROXY的NTLM算法中使用的NTLM v2 session算法。                        *
 *                                                                                      *
 ****************************************************************************************/
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdarg.h>
#include "arithmetic.h"

/******************************* NTLM-v2 session 算法 begin *****************************/


void ntlmv2_session_response(IN char * passwd, IN unsigned char * chanllenge,
                             IN unsigned char * client_nonce,
                             OUT unsigned char * ntlm_response, OUT int * ntlm_response_len,
							 OUT unsigned char * lm_response,OUT int * lm_response_len){
	unsigned char buf[21],hash[16],*c;
	int len = 0;

	//The challenge is null-padded to 24 bytes,
	//This value is placed in the LM response field of the Type 3 message.
	memset(lm_response,0,24);
	memcpy(lm_response,client_nonce,8);
	if(lm_response_len != NULL)
		* lm_response_len = 24;

	//The challenge from the Type 2 message is concatenated with the client nonce
	//Applying the MD5 digest to this nonce yields the 16-byte value.
	//This is truncated to 8 bytes to obtain the NTLM2 session hash
	memcpy(buf,chanllenge,8);
	memcpy(buf+8,client_nonce,8);
	MD5String((char*)buf,16,hash);

	//The Unicode mixed-case password,applying the MD4 digest to this value gives 
	//us the NTLM hash,This is null-padded to 21 bytes.
	len = strlen(passwd);
	c = (unsigned char *) malloc(len * 2);
	unicode(passwd, len, (char *)c, NULL);
	memset(buf,0,21);
	MD4String((char*)c,2 * len ,buf);
	free(c);

	//This value is split into three 7-byte thirds,These values are used to create 
	//three DES keys .Each of these three keys is used to DES-encrypt the NTLM2 
	//session hash,These three ciphertext values are concatenated to form the 24-byte 
	//NTLM2 session response
	algorithm_des_56key(hash,buf,ntlm_response);
	algorithm_des_56key(hash,buf +7 ,ntlm_response+8);
	algorithm_des_56key(hash,buf +14 ,ntlm_response+16);

	if(ntlm_response_len != NULL)
		* ntlm_response_len = 24;
}
