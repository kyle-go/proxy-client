#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wei_util.h"

/* 出现某个字符串的次数 */
int wei_util_get_str_num(char* buf, const char* ch) {
	int num = 0;
	char* a = buf, *b = NULL;
	while ((b = strstr(a, ch)) != NULL) {
		num++;
		a = b + strlen(ch);
	}
	return num;
}

/* 本函数字符串B的长度一定要小于字符串A的长度，或者src由足够的存储空间 */
int  wei_util_replace_all(char* str, const char* a, const char* b) {
	char* c;
	int offset = strlen(a) - strlen(b);
	if (offset < 0)
		return 0;
	while ((c = strstr(str, a)) != NULL) {
		sprintf(c, "%s%s", b, c + strlen(a));
	}
	return 0;
}

/* 本函数将影响原始的buf，所以要特别注意，可以使用用副本 */
int wei_util_split(char* buf, const char* ch, int num, char** dst) {
	char* a = buf, *b = buf;
	int i;
	for (i = 0; i < num; i++) {
		b = strstr(a, ch);
		if (i == num - 1) {
			dst[i] = a;
		}
		else if (b == NULL) {
			return 0;
		}
		else {
			dst[i] = a;
			a = b + strlen(ch);
			b[0] = 0;
		}
	}
	return 1;
}

/* 检查是否全部是数字 */
int wei_util_check_allnum(char* a) {
	if (a == NULL || strlen(a) == 0)
		return 0;
	unsigned int i;
	for (i = 0; i < strlen(a); i++) {
		if (a[i]<'0' || a[i]>'9')
			return 0;
	}
	return 1;
}
/* 对每一个头部进行如下处理，去掉字符串的前后空格 */
void wei_util_str_trim(char* a) {
	char* temp = NULL, *p = NULL, *e = NULL;
	if (a == NULL || strlen(a) == 0)
		return;
	temp = (char*)malloc(strlen(a) + 1);
	memset(temp, 0, sizeof(temp));
	p = a;
	while (p[0] == ' ') {
		p++;
	}
	e = a + strlen(a) - 1;
	while (*e == ' ') {
		e--;
	}
	memcpy(temp, p, strlen(p) - strlen(e) + 1);
	strcpy(a, p);
	free(temp);
}

/* 字符串比较，可以选择是否忽视大小写，也可以选择比较的长度，当长度小于0时，全比较 */
int wei_util_str_compare(const char* a, const char* b, int isCase, int length) {
	if (isCase)
		return length <= 0 ? strcmp(a, b) == 0 : strncmp(a, b, length) == 0;
	else
		return length <= 0 ? _stricmp(a, b) == 0 : _strnicmp(a, b, length) == 0;
	if (isCase)
		return length <= 0 ? strcmp(a, b) == 0 : strncmp(a, b, length) == 0;
	int len_a = strlen(a);
	int len_b = strlen(b);
	if (length <= 0 && len_a != len_b)
		return 0;
	else if (length > 0 && (len_a < length || len_b < length))
		return 0;
	if (length <= 0)
		length = len_a;
	int step = 'a' - 'A';

	int i;
	for (i = 0; i < length; i++) {
		if (a[i] != b[i]) {
			if (a[i] - b[i] == step && a[i] >= 'a' && a[i] <= 'z')
				continue;
			if (b[i] - a[i] == step && a[i] >= 'A' && a[i] <= 'Z')
				continue;
			return 0;
		}
	}
	return 1;
}

/* b忽略前后空格和a比较 */
int wei_util_str_compare_trim(char* a, const char* b, int is_case) {
	char* h = a;
	char* e = a + strlen(a) - 1;
	while (*h == ' ')
		h++;
	while (*e == ' ')
		e--;
	if (strlen(b) != (unsigned int)(e - h) + 1)
		return 0;
	if (is_case)
		return strncmp(h, b, strlen(b)) == 0;
	int step = 'a' - 'A';

	unsigned int i;
	for (i = 0; i < strlen(b); i++) {
		if (h[i] != b[i]) {
			if (h[i] - b[i] == step && h[i] >= 'a' && h[i] <= 'z')
				continue;
			if (b[i] - h[i] == step && h[i] >= 'A' && h[i] <= 'Z')
				continue;
			return 0;
		}
	}
	return 1;
}
