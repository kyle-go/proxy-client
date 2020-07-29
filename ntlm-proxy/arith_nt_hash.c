/****************************************************************************************
 *                                                                                      *
 * 本源代码用于HTTP PROXY的NTLM算法中使用的NT-HASH算法。                                *
 *                                                                                      *
 ****************************************************************************************/
#include <string.h>
#include <stdlib.h>
#include "arithmetic.h"

/********************************* NT-HASH 算法 begin *****************************/
void nt_hash(IN char * src, IN int is_unicode,OUT unsigned char * dst, OUT int * dst_len){
	char * source = NULL;
	int len = strlen(src);
	if(!is_unicode){
		source = (char * ) malloc(len *2 );
		unicode(src,len,source,&len);
	}else{
		source = src;
	}

	MD4String (source,len,dst);
	if(dst_len != NULL)
		* dst_len = 16;

	if(!is_unicode)
		free(source);
}
