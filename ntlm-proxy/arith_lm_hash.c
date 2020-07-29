/****************************************************************************************
 *                                                                                      *
 * 本源代码用于HTTP PROXY的NTLM算法中使用的LM-HASH算法。                                *
 *                                                                                      *
 ****************************************************************************************/
#include <string.h>
#include "arithmetic.h"

/********************************* LM-HASH 算法 begin *****************************/
static unsigned char lm_magic[] = { 0x4B, 0x47, 0x53, 0x21, 0x40, 0x23, 0x24, 0x25 };
/*
* from The Samba Team's source/libsmb/smbdes.c
*/
static void str_to_key ( IN const unsigned char *str, OUT unsigned char *key )
{
	unsigned int i;
	key[0] = str[0] >> 1;
	key[1] = ( ( str[0] & 0x01 ) << 6 ) | ( str[1] >> 2 );
	key[2] = ( ( str[1] & 0x03 ) << 5 ) | ( str[2] >> 3 );
	key[3] = ( ( str[2] & 0x07 ) << 4 ) | ( str[3] >> 4 );
	key[4] = ( ( str[3] & 0x0F ) << 3 ) | ( str[4] >> 5 );
	key[5] = ( ( str[4] & 0x1F ) << 2 ) | ( str[5] >> 6 );
	key[6] = ( ( str[5] & 0x3F ) << 1 ) | ( str[6] >> 7 );
	key[7] = str[6] & 0x7F;
	for ( i = 0; i < 8; i++ )
	{
		key[i] = ( key[i] << 1 );
	}
	return;
}/* end of str_to_key */


//获取16字节的lm-hash内容
void lm_hash(IN char * src, OUT unsigned char * dst, OUT int * dst_len){
	int i = 0;
	unsigned char lm_src[14];

	if(strlen(src) >= 14){
		memcpy(lm_src,src,14);
	}else{
		memset(lm_src,0,14);
		memcpy(lm_src,src,strlen(src));
	}
	for(i = 0 ;i < 14; i ++){
	  lm_src[i] = chrtoupper(lm_src[i]);
	}
/*
	//str_to_key(lm_src,key);
	str_to_key(lm_src,dst);
	//str_to_key(lm_src + 7, key);
	str_to_key(lm_src + 7, dst + 8);

	algorithm_des(lm_magic, dst,dst);
	algorithm_des(lm_magic, dst + 8,dst + 8);
	*/
	algorithm_des_56key(lm_magic, lm_src,dst);
	algorithm_des_56key(lm_magic, lm_src + 7,dst + 8);
	if(dst_len != NULL)
		* dst_len = 16;
}

//LM-HASH end
