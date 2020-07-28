#pragma once
#include <string>

/*
// base64±àÂë
static std::string encode(const std::string& str);
static std::string encode(void *data, int len);

// base64½âÂë£¬Èô×Ö·û´®²»±ê×¼·µ»Ø¿Õ×Ö·û´®
static std::string decode(const std::string& s);

// ÅĞ¶Ï×Ö·û´®ÊÇ·ñÊÇ±ê×¼base64±àÂë
static bool is_base64_string(const char *input);
*/

namespace common {
    struct base64 {
        static std::string encode(const std::string& str) {
            return encode((unsigned char*)str.c_str(), str.length());
        }

        static std::string encode(void *data, int len) {
            char *buf = base64_encode((unsigned char*)data, len);
            std::string r(buf);
            delete[] buf;
            return r;
        }

        static std::string decode(const std::string& s) {
            if (!is_base64_string(s.c_str())) {
                return "";
            }

            int len;
            auto buf = base64_decode(s.c_str(), s.length(), &len);
            std::string r((char *)buf, len);
            delete[] buf;
            return r;
        }

        static bool is_base64_string(const char *input) {
            const int inputLen = strlen(input);
            int outlen = 0;
            unsigned char *src = base64_decode(input, inputLen, &outlen);
            char *dst = base64_encode(src, outlen);
            if (strlen(dst) != inputLen) {
                delete[] src;
                delete[] dst;
                return false;
            }

            bool result = (memcmp(dst, input, inputLen) == 0);
            delete[] src;
            delete[] dst;
            return result;
        }

    private:
        static char * base64_encode(const unsigned char *input, int length) {
            const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            int i = 0, j = 0, s = 0;
            unsigned char char_array_3[3], char_array_4[4];

            int b64len = (length + 2 - ((length + 2) % 3)) * 4 / 3;
            char *b64str = (char *)malloc(b64len + 1);
            if (b64str == NULL)
                return NULL;

            while (length--) {
                char_array_3[i++] = *(input++);
                if (i == 3) {
                    char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
                    char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
                    char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
                    char_array_4[3] = char_array_3[2] & 0x3f;

                    for (i = 0; i < 4; i++)
                        b64str[s++] = base64_chars[char_array_4[i]];

                    i = 0;
                }
            }
            if (i) {
                for (j = i; j < 3; j++)
                    char_array_3[j] = '\0';

                char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
                char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
                char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
                char_array_4[3] = char_array_3[2] & 0x3f;

                for (j = 0; j < i + 1; j++)
                    b64str[s++] = base64_chars[char_array_4[j]];

                while (i++ < 3)
                    b64str[s++] = '=';
            }
            b64str[b64len] = '\0';
            return b64str;
        }

        static unsigned char *base64_decode(const char *input, int length, int *outlen) {
            const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            auto is_base64 = [](unsigned char c) {
                return (isalnum(c) || (c == '+') || (c == '/'));
            };

            int i = 0;
            int j = 0;
            int r = 0;
            int idx = 0;
            unsigned char char_array_4[4], char_array_3[3];
            unsigned char *output = (unsigned char *)malloc(length * 3 / 4);

            while (length-- && input[idx] != '=') {
                //skip invalid or padding based chars
                if (!is_base64(input[idx])) {
                    idx++;
                    continue;
                }
                char_array_4[i++] = input[idx++];
                if (i == 4) {
                    for (i = 0; i < 4; i++)
                        char_array_4[i] = strchr(base64_chars.c_str(), char_array_4[i]) - base64_chars.c_str();

                    char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
                    char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
                    char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

                    for (i = 0; (i < 3); i++)
                        output[r++] = char_array_3[i];
                    i = 0;
                }
            }

            if (i) {
                for (j = i; j < 4; j++)
                    char_array_4[j] = 0;

                for (j = 0; j < 4; j++)
                    char_array_4[j] = strchr(base64_chars.c_str(), char_array_4[j]) - base64_chars.c_str();

                char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
                char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
                char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

                for (j = 0; (j < i - 1); j++)
                    output[r++] = char_array_3[j];
            }

            *outlen = r;
            return output;
        }
    };
}
