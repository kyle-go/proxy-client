
#if (defined WIN32) || (defined _WIN64)
#include <winsock2.h>
#pragma comment(lib,"ws2_32.lib")
#endif

#ifdef LINUX
#include <netinet/in.h>
#endif
#include "httppc_ntlm.h"

#include "arithmetic.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
/************************************ part1: NTLM 算法 **********************************/
/*
static void tempPrintLen(unsigned char * buf,int len ){
	LOG(LOG_DEBUG,"========二进制输出 长度：%d",len);
	int line = len/8;
	if(line * 8 != len)
		line ++;
	for(int i = 0 ; i <line ; i ++){
		LOG(LOG_DEBUG,"%d   %02x %02x %02x %02x %02x %02x %02x %02x",i*8,
			(unsigned char)buf[8*i],(unsigned char)buf[8*i+1],(unsigned char)buf[8*i+2],
			(unsigned char)buf[8*i+3],(unsigned char)buf[8*i+4],(unsigned char)buf[8*i+5],
			(unsigned char)buf[8*i+6],(unsigned char)buf[8*i+7]);
	}
}
*/
PRIVATE void wei_ntlm_make_type1(IN bool is_little_endian,IN char * domain,IN char * name,
								 IN int author_type,OUT T_NTLM_TYPE_1_MSG * info){
	short int domain_len = 0,name_len = 0;
	unsigned int flags;

	if(domain != NULL)
		domain_len = strlen(domain);
	if(name != NULL)
		name_len = strlen(name);

	if(info == NULL)
		return;
	memset(info,0,sizeof(T_NTLM_TYPE_1_MSG));
	strcpy(info->protocol,"NTLMSSP");
	info->type = is_little_endian ? 0x01 : htonl(0x01);
	switch(author_type){
	case AUTHOR_NTLM_2:
		flags = 0x0280b205;
		break;
	case AUTHOR_NTLM_SESSION:
		//flags = 0x0288b201;
		//flags=0x00088207;
		flags = 0xa2088207;
		break;
	case AUTHOR_NTLM_1:
	default:
		flags = 0xb201;
		break;
	}
	//if(domain_len == 0)
	//	flags -= 0x1000;
	//if(name_len == 0)
	//	flags -= 0x2000;
	info->flags = is_little_endian ? flags : htonl(flags);

//	info->flags = is_little_endian ? 0x00088207 : htonl(0x00088207);
	//info->dom_len1  = is_little_endian ? domain_len : htonl(domain_len);
	//info->dom_len2  = info->dom_len1;
	//info->dom_off   = is_little_endian ? 0x20 + name_len : htonl((short)(0x20 + name_len));
	//info->host_len1 = is_little_endian ? name_len : htons(name_len);
	//info->host_len2 = info->host_len1;
	//info->host_off  = is_little_endian ? 0x20 : htonl(0x20);
	//info->dom = domain;
	//info->host = name;
}
/*
unsigned char target[] = {0x02,0x00,0x0c,0x00,0x44,0x00,0x4f,0x00,
  0x4d,0x00,0x41,0x00,0x49,0x00,0x4e,0x00,
  0x01,0x00,0x0c,0x00,0x53,0x00,0x45,0x00,
  0x52,0x00,0x56,0x00,0x45,0x00,0x52,0x00,
  0x04,0x00,0x14,0x00,0x64,0x00,0x6f,0x00,
  0x6d,0x00,0x61,0x00,0x69,0x00,0x6e,0x00,
  0x2e,0x00,0x63,0x00,0x6f,0x00,0x6d,0x00,
  0x03,0x00,0x22,0x00,0x73,0x00,0x65,0x00,
  0x72,0x00,0x76,0x00,0x65,0x00,0x72,0x00,
  0x2e,0x00,0x64,0x00,0x6f,0x00,0x6d,0x00,
  0x61,0x00,0x69,0x00,0x6e,0x00,0x2e,0x00,
  0x63,0x00,0x6f,0x00,0x6d,0x00,0x00,0x00,
  0x00,0x00};
unsigned char client_nounce[] = {
	0xff,0xff,0xff,0x00,0x11,0x22,0x33,0x44
};
*/
void wei_ntlm_make_type1_base64(IN bool is_little_endian,IN char * domain,IN char * host_name,
								IN int author_type,OUT char * buf){
	int ntlm_len = 0,domain_len = 0 ,host_name_len = 0;
	char * ntlm_buff = NULL;
	T_NTLM_TYPE_1_MSG info;

	if(domain != NULL)
		 domain_len = strlen(domain);
	if(host_name != NULL)
		host_name_len = strlen(host_name);

	wei_ntlm_make_type1(is_little_endian,domain,host_name,author_type,&info);

	ntlm_len = 32 + domain_len + host_name_len + 8;
	ntlm_buff = (char *) malloc(ntlm_len);
	memset(ntlm_buff,0, ntlm_len);
	memcpy(ntlm_buff,&info,32);
	
	if(host_name_len != 0)
		memcpy(ntlm_buff + 32,info.host,host_name_len);

	if(domain_len != 0)
		memcpy(ntlm_buff + 32 + host_name_len,info.dom,domain_len);

	ntlm_buff[32] = 0x0a;
	ntlm_buff[33] = 0x00;
	ntlm_buff[34] = 0x61;
	ntlm_buff[35] = 0x4a;
	ntlm_buff[39] = 0x0f;
	encode_base64(buf,ntlm_buff,ntlm_len);
	//对长度进行处理
	free(ntlm_buff);
	/*
	//void lm_hash(IN char * src, OUT char * dst, OUT int * len);
	unsigned char dst[16],response[48],challenge[8],rn[256],lm[256];
	int rn_len,lm_len;
	//lm_hash("Beebleb",(char *) key,NULL);
	lm_hash("Beeblebrox",dst,NULL);
	tempPrintLen(dst,16);
	nt_hash("Beeblebrox",0,dst,NULL);
	tempPrintLen(dst,16);
	//"Beeblebrox"
	challenge[0] = 0x01;
	challenge[1] = 0x23;
	challenge[2] = 0x45;
	challenge[3] = 0x67;
	challenge[4] = 0x89;
	challenge[5] = 0xab;
	challenge[6] = 0xcd;
	challenge[7] = 0xef;
	ntlmv1_response("SecREt01", challenge, response,NULL);
	tempPrintLen(response,48);
	ntlmv2_response("SecREt01", "user","DOMAIN",challenge, target,98,client_nounce,
					rn,&rn_len,lm,&lm_len);
	tempPrintLen(rn,rn_len);
	tempPrintLen(lm,lm_len);

	ntlmv2_session_response("SecREt01",challenge,client_nounce,
                             rn,&rn_len,lm,&lm_len);
	tempPrintLen(rn,rn_len);
	tempPrintLen(lm,lm_len);*/
}

/* 获取type2的结构，并进行校验 */
bool wei_ntlm_decode_type2(IN bool is_little_endian,IN char * info, OUT T_NTLM_TYPE_2_MSG * type2){
	unsigned char buf[256] = {0};
	int type_len;
	decode_base64(info,strlen(info),(char *)buf,&type_len);
	
	memcpy(type2,buf,48);
	/* 假设这个时候已经解码完成，这样的话需要给type赋值 */
	if(strcmp(type2->protocol,"NTLMSSP") != 0)
		return false;

	if(!is_little_endian){
		type2->target_name_len = htons(type2->target_name_len);
		type2->target_name_allocation = htons(type2->target_name_allocation);
		type2->target_name_offset = htonl(type2->target_name_offset);
		type2->flags = htonl(type2->flags);
		type2->target_info_len = htons(type2->target_info_len);
		type2->target_info_alloction = htons(type2->target_info_alloction);
		type2->target_info_offset = htons(type2->target_info_offset);
	}
	
	if((type2->target_info_offset + type2->target_info_len > type_len) ||
		(type2->target_name_offset + type2->target_name_len > type_len))
		return false;

	if(type2->target_info_len != 0 && type2->target_info_offset > 0){
		type2->target_info = (unsigned char *)malloc(type2->target_info_len);
		memcpy(type2->target_info,buf + type2->target_info_offset,type2->target_info_len);
	}else
		type2->target_info = NULL;


	if(type2->target_name_len != 0 && type2->target_name_offset > 0)
		type2->target_name = buf + type2->target_name_offset;
	else
		type2->target_name = NULL;
	
	return true;
}



PRIVATE void create_nonce(OUT unsigned char * nonce){
#ifdef _LINUX
	srandom(time(0));
#else
	srand(time(0));
#endif
	int i;
	for(i = 0 ; i< 8 ; i ++){
		nonce[i] = rand() * 1.0 /RAND_MAX * 256;
	}
}

bool wei_ntlm_make_type3_base64(IN bool is_little_endian,IN char * domain ,IN char * host, IN char * user, 
						IN char * passwd, IN T_NTLM_TYPE_2_MSG * type2_msg,OUT char * buf){
	T_NTLM_TYPE_3_MSG msg;
	unsigned char client_nonce[8],lm_response[256],ntlm_response[512];
	int author_type = AUTHOR_NTLM_1,lm_len = 0,ntlm_len = 0,offset = 0,len = 0;
	unsigned int flags = 0;
	char * pure_response;

	if((type2_msg->flags & 0x800000) != 0){
		author_type = AUTHOR_NTLM_2;
		if((type2_msg->flags & 0x80000) != 0)
			author_type = AUTHOR_NTLM_SESSION;
	}

	memset(&msg,0,sizeof(T_NTLM_TYPE_3_MSG));
	strcpy((char *)msg.protocol,"NTLMSSP");
	msg.type = is_little_endian ? 0x03 : htonl(0x03);

	switch(author_type){
	case AUTHOR_NTLM_2:

	//	LOG(LOG_DEBUG,"TYPE NTLM V2");
		create_nonce(client_nonce);
		//tempPrintLen(client_nonce,8);
		//tempPrintLen(type2_msg->target_info,type2_msg->target_info_len);
		ntlmv2_response(passwd,user,domain,type2_msg->nonce,type2_msg->target_info,
		                type2_msg->target_info_len,client_nonce,
		                ntlm_response,&ntlm_len,lm_response, &lm_len);
		flags = 0x0280b205;
		break;
	case AUTHOR_NTLM_SESSION:
		//LOG(LOG_DEBUG,"TYPE NTLM Session V2");
		create_nonce(client_nonce);
		ntlmv2_session_response(passwd, type2_msg->nonce,client_nonce,
		                        ntlm_response,&ntlm_len,lm_response, &lm_len);
		flags = 0x0288b201;
		break;
	case AUTHOR_NTLM_1:
	default:
		ntlmv1_response(passwd,type2_msg->nonce,ntlm_response,&ntlm_len,lm_response, 
		                &lm_len);
		flags = 0xb201;
		break;
	}

	//domain
	offset = 64;
	if(domain != NULL && strlen(domain) != 0){
		len = strlen(domain) *2;
		msg.domain_len = is_little_endian ? len : htons(len);
		msg.domain_allocation = msg.domain_len;
		msg.domain_offset = is_little_endian ? offset : htonl(offset);
		offset += len;
		msg.domain = (char *) malloc(len);
		unicode(domain,strlen(domain),msg.domain,NULL);
	}else{
		msg.domain_offset = is_little_endian ? offset : htonl(offset);
		flags -= 0x1000;
	}

	//user
	if(user != NULL && strlen(user) != 0){
		len = strlen(user) * 2;
		msg.user_len = is_little_endian ? len : htons(len);
		msg.user_allocation = msg.user_len;
		msg.user_offset = is_little_endian ? offset : htonl(offset);
		offset += len;
		msg.user = (char *) malloc(len);
		unicode(user,strlen(user),msg.user,NULL);
	}else{
		msg.user_offset = is_little_endian ? offset : htonl(offset);
	}

	//host
	if(host != NULL && strlen(host) != 0){
		len = strlen(host) * 2;
		msg.host_len = is_little_endian ? len : htons(len);
		msg.host_allocation = msg.host_len;
		msg.host_offset = is_little_endian ? offset : htonl(offset);
		offset += len;
		msg.host = (char * ) malloc(len);
		unicode(host,strlen(host),msg.host,NULL);
	}else{
		msg.host_offset = is_little_endian ? offset : htonl(offset);
		flags -= 0x2000;
	}
	
	//lm_response
	msg.lm_resp_len = is_little_endian ? lm_len : htons(lm_len);
	msg.lm_resp_allocation = msg.lm_resp_len;
	msg.lm_resp_offset = is_little_endian ? offset : htonl(offset);
	offset += lm_len;
	msg.lm_resp = lm_response;

	//ntlm_response
	msg.nt_resp_len = is_little_endian ? ntlm_len : htons(ntlm_len);
	msg.nt_resp_allocation = msg.nt_resp_len;
	msg.nt_resp_offset = is_little_endian ? offset : htonl(offset);
	offset += ntlm_len;
	msg.nt_resp = ntlm_response;

	//others
	msg.flags = is_little_endian ? flags : htonl(flags);
	msg.msg_len = is_little_endian ? offset : htonl(offset);
	len = offset;


	pure_response = (char *) malloc(len);
	memcpy(pure_response,&msg,64);
	offset = 64;
	if(msg.domain != NULL){
		memcpy(pure_response + offset , msg.domain, strlen(domain) *2);
		offset += strlen(domain) *2;
	}
	if(msg.user != NULL){
		memcpy(pure_response + offset , msg.user, strlen(user) *2);
		offset += strlen(user) *2;
	}
	if(msg.host != NULL){
		memcpy(pure_response + offset , msg.host, strlen(host) *2);
		offset += strlen(host) *2;
	}
	memcpy(pure_response + offset , msg.lm_resp, lm_len);
	offset += lm_len;
	memcpy(pure_response + offset , msg.nt_resp, ntlm_len);

	encode_base64(buf,pure_response,len);
	free(pure_response);
	free(msg.domain);
	free(msg.user);
	free(msg.host);
	return true;
}
// end of part3: NTML 算法

