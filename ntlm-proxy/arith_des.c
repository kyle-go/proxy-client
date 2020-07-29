/****************************************************************************************
 * 本源代码用于HTTP PROXY的NTLM算法中DES算法                                            *
 ****************************************************************************************/
#include <string.h>
#include <stdlib.h>
#include "arithmetic.h"

static int ip_data_seq[] = {
	58,50,42,34,26,18,10,2,
	60,52,44,36,28,20,12,4,
	62,54,46,38,30,22,14,6,
	64,56,48,40,32,24,16,8,
	57,49,41,33,25,17,9,1 ,
	59,51,43,35,27,19,11,3,
	61,53,45,37,29,21,13,5,
	63,55,47,39,31,23,15,7};
static int ip_key_seq[] ={
	57,49,41,33,25,17,9,
	1, 58,50,42,34,26,18,
	10,2, 59,51,43,35,27,
	19,11,3, 60,52,44,36,
	63,55,47,39,31,23,15,
	7, 62,54,46,38,30,22,
	14,6, 61,53,45,37,29,
	21,13,5, 28,20,12,4};
static int ip_56key_seq[] ={
	50,43,36,29,22,15,8,
	1, 51,44,37,30,23,16,
	9, 2, 52,45,38,31,24,
	17,10,3, 53,46,39,32,
	56,49,42,35,28,21,14,
	7, 55,48,41,34,27,20,
	13, 6,54,47,40,33,26,
	19,12,5, 25,18,11,4};//处理了1－7，8－14，15-21，22-28，29-35，36-42，43-56};

static int key_offset[] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};
static int ip_key[] ={
	14,17,11,24,1,5,
	3,28,15,6,21,10,
	23,19,12,4,26,8,
	16,7,27,20,13,2,
	41,52,31,37,47,55,
	30,40,51,45,33,48,
	44,49,39,56,34,53,
	46,42,50,36,29,32};
static int ip_e[] = {
	32,1,2,3,4,5,
	4,5,6,7,8,9,
	8,9,10,11,12,13,
	12,13,14,15,16,17,
	16,17,18,19,20,21,
	20,21,22,23,24,25,
	24,25,26,27,28,29,
	28,29,30,31,32,1};
static int ip_p[] = {
	16,7,20,21,
	29,12,28,17,
	1,15,23,26,
	5,18,31,10,
	2,8,24,14,
	32,27,3,9,
	19,13,30,6,
	22,11,4,25};

static int inverse_ip_p[64] = {
	40,8,48,16,56,24,64,32,
	39,7,47,15,55,23,63,31,
	38,6,46,14,54,22,62,30,
	37,5,45,13,53,21,61,29,
	36,4,44,12,52,20,60,28,
	35,3,43,11,51,19,59,27,
	34,2,42,10,50,18,58,26,
	33,1,41,9,49,17,57,25};

static unsigned char s1[64] /*[4][16]*/ = {
	14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
	0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
	4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
	15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 };
/* Table - s2 */
static unsigned char s2[64] /*[4][16]*/ = {
	15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
	3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
	0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
	13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 };
/* Table - s3 */
static unsigned char s3[64] /*[4][16]*/ = {
	10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
	13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
	13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
	1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 };
/* Table - s4 */
static unsigned char s4[64] /*[4][16]*/ = {
	7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
	13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
	10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
	3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 };
/* Table - s5 */
static unsigned char s5[64] /*[4][16]*/ = {
	2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
	14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
	4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
	11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 };
/* Table - s6 */
static unsigned char s6[64] /*[4][16]*/ = {
	12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
	10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
	9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
	4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 };
/* Table - s7 */
static unsigned char s7[64] /*[4][16]*/ = {
	4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
	13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
	1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
	6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 };
/* Table - s8 */
static unsigned char s8[64] /*[4][16]*/ = {
	13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
	1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
	7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
	2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 };


static unsigned char getbit(unsigned char a, int offset){
	switch(offset){
	case 0:
		return (a & 0x1) == 0 ? 0 : 1;
	case 1:
		return (a & 0x2) == 0 ? 0 : 1;
	case 2:
		return (a & 0x4) == 0 ? 0 : 1;
	case 3:
		return (a & 0x8) == 0 ? 0 : 1;
	case 4:
		return (a & 0x10) == 0 ? 0 : 1;
	case 5:
		return (a & 0x20) == 0 ? 0 : 1;
	case 6:
		return (a & 0x40) == 0 ? 0 : 1;
	case 7:
		return (a & 0x80) == 0 ? 0 : 1;
	default:
		return 0;
	}
}

static void storebit(IN unsigned char * data, IN int data_len, OUT unsigned char * dst){
	int i = 0;
	for(i = 0 ; i < data_len;i ++){
		dst[i*8] = getbit(data[i],7);
		dst[i*8 + 1] = getbit(data[i],6);
		dst[i*8 + 2] = getbit(data[i],5);
		dst[i*8 + 3] = getbit(data[i],4);
		dst[i*8 + 4] = getbit(data[i],3);
		dst[i*8 + 5] = getbit(data[i],2);
		dst[i*8 + 6] = getbit(data[i],1);
		dst[i*8 + 7] = getbit(data[i],0);
	}
}

static void parsebit(IN unsigned char * data,OUT unsigned char * dst,IN int dst_len){
	int i = 0;
	for(i = 0 ; i < dst_len ; i ++){
		dst[i] = data[8*i] * 0x80 + 
			data[8*i + 1] * 0x40 + 
			data[8*i + 2] * 0x20 + 
			data[8*i + 3] * 0x10 + 
			data[8*i + 4] * 0x8 + 
			data[8*i + 5] * 0x4 + 
			data[8*i + 6] * 0x2 + 
			data[8*i + 7];
	}
}

static void xorbit(IN unsigned char * a, IN unsigned char * b ,IN int len,
				   OUT unsigned char * c){
	unsigned char * temp = (unsigned char *) malloc(len);
	int i = 0;
	for(i = 0 ; i < len ; i ++){
		if(a[i] + b[i] == 1)
			temp[i] = 1;
		else
			temp[i] = 0;
	}
	memcpy(c,temp,len);
	free(temp);
}


//对输入的64比特（8字节）的data进行序列变化,dst的数组长度为64
static void initail_permutation(IN unsigned char * data,IN int * schedule, IN int num,
								OUT unsigned char * dst){
	int i = 0;
	unsigned char * temp;
	temp = (unsigned char *)malloc(num);

	for(i = 0 ; i < num; i ++){
		temp[i] = data[schedule[i] - 1];
	}
	memcpy(dst,temp,num);
	free(temp);
}


static void getkey(IN OUT unsigned char * key,int offset){
	unsigned char temp[28];//后面的28bit

	memcpy(temp,key + offset,28-offset);
	memcpy(temp + 28 - offset, key , offset);
	memcpy(key,temp,28);

	memcpy(temp,key + 28 + offset,28-offset);
	memcpy(temp + 28 - offset, key + 28 , offset);
	memcpy(key + 28,temp,28);
}

static void s_box_function(IN unsigned char * data,IN unsigned char * sbox,OUT unsigned char * dst){
	int m = data[0] * 2 + data[5];
	int n = data[1] * 8 + data[2] * 4 + data[3] * 2 + data[4];
	unsigned char c = sbox[m* 16 + n];
	if(c >= 8){
		dst[0] = 1;
		c = c-8;
	}else{
		dst[0] = 0;
	}
	if(c >= 4){
		dst[1] = 1;
		c = c-4;
	}else{
		dst[1] = 0;
	}
	if(c >= 2){
		dst[2] = 1;
		c = c-2;
	}else{
		dst[2] = 0;
	}
	dst[3] = c;
}

void algorithm_des(IN unsigned char * src, IN unsigned char * secrect,
                   OUT unsigned char * dst){
	unsigned char s[64],key[64],L[32],R[32],K[48],E[48];
	int i = 0;

	storebit(src,8,s);
	storebit(secrect,8,key);

	//step1: initial permutation src and key
	initail_permutation(s,ip_data_seq,64,s);
	initail_permutation(key,ip_key_seq,56,key);
	

	//step2:16次计算
	//获取原始的L0和R0
	memcpy(L,s,32);
	memcpy(R,s+32,32);

	//进行16次计算
	for(i = 0; i < 16 ; i++){
		//获取K
		getkey(key,key_offset[i]);
		initail_permutation(key,ip_key,48,K);

		//F计算
		initail_permutation(R,ip_e,48,E);
		//E[I] XOR K[I]
		xorbit(E,K,48,E);

		s_box_function(E,s1,E);
		s_box_function(E + 6,s2,E + 4);
		s_box_function(E + 12,s3,E + 8);
		s_box_function(E + 18,s4,E + 12);
		s_box_function(E + 24,s5,E + 16);
		s_box_function(E + 30,s6,E + 20);
		s_box_function(E + 36,s7,E + 24);
		s_box_function(E + 42,s8,E + 28);
		// OK , now get 32bits E
		initail_permutation(E,ip_p,32,E);
		xorbit(E,L,32,E);
		memcpy(L,R,32);
		memcpy(R,E,32);
	}

	memcpy(s,R,32);
	memcpy(s+32,L,32);
	initail_permutation(s,inverse_ip_p,64,s);
	parsebit(s,dst,8);
}

void algorithm_des_56key(IN unsigned char * src, IN unsigned char * secrect,
						 OUT unsigned char * dst){
	unsigned char s[64],key[64],L[32],R[32],K[48],E[48];
	int i = 0;

	storebit(src,8,s);
	storebit(secrect,8,key);
	//step1: initial permutation src and key
	initail_permutation(s,ip_data_seq,64,s);
	initail_permutation(key,ip_56key_seq,56,key);
	

	//step2:16次计算
	//获取原始的L0和R0
	memcpy(L,s,32);
	memcpy(R,s+32,32);

	//进行16次计算
	for(i = 0; i < 16 ; i++){
		//获取K
		getkey(key,key_offset[i]);
		initail_permutation(key,ip_key,48,K);

		//F计算
		initail_permutation(R,ip_e,48,E);
		//E[I] XOR K[I]
		xorbit(E,K,48,E);

		s_box_function(E,s1,E);
		s_box_function(E + 6,s2,E + 4);
		s_box_function(E + 12,s3,E + 8);
		s_box_function(E + 18,s4,E + 12);
		s_box_function(E + 24,s5,E + 16);
		s_box_function(E + 30,s6,E + 20);
		s_box_function(E + 36,s7,E + 24);
		s_box_function(E + 42,s8,E + 28);
		// OK , now get 32bits E
		initail_permutation(E,ip_p,32,E);
		xorbit(E,L,32,E);
		memcpy(L,R,32);
		memcpy(R,E,32);
	}

	memcpy(s,R,32);
	memcpy(s+32,L,32);
	initail_permutation(s,inverse_ip_p,64,s);
	parsebit(s,dst,8);
}
