/****************************************************************************************
 * 本源代码用于HTTP PROXY的NTLM算法中使用的通用函数                                     *
 ****************************************************************************************/
#include <string.h>
#include "arithmetic.h"

static unsigned char upper_step = 'a' - 'A';

char chrtoupper(IN char a){
	if( a >= 'a' && a <= 'z')
		return a - upper_step;
	return a;
}

char * strtoupper(IN OUT char * a){
	int i = 0;
	int len = strlen(a);
	for(i = 0 ; i < len ; i ++){
		a[i] = chrtoupper(a[i]);
	}
	return a;
}


void unicode(IN char * src, IN int src_len, OUT char * dst, OUT int * dst_len){
	int i ;
	for( i = 0 ; i < src_len; i ++){
		dst[2*i] = src[i];
		dst[2*i +1] = 0;
	}
	if(dst_len != NULL)
		* dst_len = src_len * 2;
}
