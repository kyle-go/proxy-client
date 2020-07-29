#ifdef __cplusplus
extern "C" {
#endif
#ifndef WEI_UTIL_H
#define WEI_UTIL_H
#ifndef IN
#define IN
#endif
#ifndef OUT
#define OUT
#endif
#ifndef PRIVATE
#define PRIVATE
#endif
// #define bool int

/****************************** 字符串处理 *********************************/
/** 检索某个字符串出现的次数 */
int wei_util_get_str_num(IN char * buf,IN const char * ch);
/** 本函数，字符串B的长度必须小于字符串A的长度。或者保证str的足够空间。*/
int wei_util_replace_all(IN OUT char * str,IN const char * a, IN const char * b);
/** 本函数将影响到原始出入的buf，提请特别注意，可以使用副本来处理。类似JAVA的split */
int wei_util_split(IN OUT char * buf,IN const char * ch, IN int num ,OUT char * * dst);
/** 检查是否都是数字*/
int  wei_util_check_allnum(IN char * a);
/** 去除字符串的前后空格 */
void wei_util_str_trim(IN OUT char * a);
/** 字符串之间的比较，可选择是否大小写敏感，以及设定比较的长度，如果为长度<=0，表示全字符串比较。*/
int  wei_util_str_compare(IN const char * a, IN const char * b,IN int isCase,IN int length);
/** a忽略前后空格和b进行比较 */
int  wei_util_str_compare_trim(char * a, const char * b, int is_case);
#endif
#ifdef __cplusplus
}
#endif
