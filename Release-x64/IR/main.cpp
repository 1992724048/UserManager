#define C_API extern "C"

// 该函数用于定位起始地址
C_API int start_address(int a, int b)
{
    return a + b;
}

#include <Windows.h>
#include "minmalloc/mimalloc.h"
#include "minmalloc/mimalloc-override.h"
#include "minmalloc/mimalloc-new-delete.h"
#include "zlib/zlib.h"
#include "xorstr.h"

#include <memory>
#include <cstdint>
#include <cstdlib>
#include <cstring>

C_API int add(int a, int b)
{
    return a + b;
}

C_API bool check_password(const char* str) {
    bool is_ = !strcmp(XORSTR("a1s2d3f4g5h6j7k8l9"), str);
    if (!is_)
    {
        MessageBoxW(nullptr, XORWSTR(L"密码错误!"), XORWSTR(L"错误"), MB_OK | MB_ICONERROR);
    } else {
        MessageBoxW(nullptr, XORWSTR(L"密码正确!"), XORWSTR(L"正确"), MB_OK | MB_USERICON);
    }
    return is_;
}

C_API int zlib_compress(const unsigned char *src, unsigned long src_len,
                        unsigned char **out, unsigned long *out_len,
                        int level)
{
    if (!src || !out || !out_len)
        return Z_STREAM_ERROR;
    if (src_len == 0)
    {
        *out = NULL;
        *out_len = 0;
        return Z_OK;
    }

    unsigned long bound = compressBound(src_len);
    unsigned char *buf = (unsigned char *)malloc(bound);
    if (!buf)
        return Z_MEM_ERROR;

    int ret = compress2(buf, &bound, src, src_len, level);
    if (ret != Z_OK)
    {
        free(buf);
        return ret;
    }

    *out = buf;
    *out_len = bound;
    return Z_OK;
}

C_API int zlib_decompress(const unsigned char *src, unsigned long src_len,
                          unsigned char **out, unsigned long *out_len,
                          unsigned long expected_size)
{
    if (!src || !out || !out_len)
        return Z_STREAM_ERROR;
    if (src_len == 0)
    {
        *out = NULL;
        *out_len = 0;
        return Z_OK;
    }

    unsigned long initial = expected_size ? expected_size : src_len * 4;
    unsigned char *buf = (unsigned char *)malloc(initial);
    if (!buf)
        return Z_MEM_ERROR;

    unsigned long dest_len = initial;
    int ret = uncompress(buf, &dest_len, src, src_len);

    if (ret == Z_BUF_ERROR && expected_size == 0)
    {
        initial = src_len * 8;
        unsigned char *tmp = (unsigned char *)realloc(buf, initial);
        if (!tmp)
        {
            free(buf);
            return Z_MEM_ERROR;
        }
        buf = tmp;
        dest_len = initial;
        ret = uncompress(buf, &dest_len, src, src_len);
    }

    if (ret != Z_OK)
    {
        free(buf);
        return ret;
    }

    *out = buf;
    *out_len = dest_len;
    return Z_OK;
}

C_API void zlib_free(unsigned char *p)
{
    free(p);
}

static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
C_API unsigned char *base64_encode(const unsigned char *data, size_t len, size_t *out_len)
{
    if (!data)
    {
        if (out_len)
            *out_len = 0;
        return NULL;
    }

    size_t full_blocks = len / 3;
    size_t rem = len % 3;
    size_t outsz = (full_blocks + (rem ? 1 : 0)) * 4;
    unsigned char *out = (unsigned char *)malloc(outsz + 1);
    if (!out)
    {
        if (out_len)
            *out_len = 0;
        return NULL;
    }

    size_t ip = 0, op = 0;
    while (ip + 3 <= len)
    {
        uint32_t v = (uint32_t)data[ip] << 16 | (uint32_t)data[ip + 1] << 8 | (uint32_t)data[ip + 2];
        out[op++] = b64_table[(v >> 18) & 0x3F];
        out[op++] = b64_table[(v >> 12) & 0x3F];
        out[op++] = b64_table[(v >> 6) & 0x3F];
        out[op++] = b64_table[v & 0x3F];
        ip += 3;
    }

    if (rem)
    {
        uint32_t v = 0;
        if (rem == 1)
        {
            v = (uint32_t)data[ip] << 16;
            out[op++] = b64_table[(v >> 18) & 0x3F];
            out[op++] = b64_table[(v >> 12) & 0x3F];
            out[op++] = '=';
            out[op++] = '=';
        }
        else
        {
            v = (uint32_t)data[ip] << 16 | (uint32_t)data[ip + 1] << 8;
            out[op++] = b64_table[(v >> 18) & 0x3F];
            out[op++] = b64_table[(v >> 12) & 0x3F];
            out[op++] = b64_table[(v >> 6) & 0x3F];
            out[op++] = '=';
        }
    }

    out[op] = '\0';
    if (out_len)
        *out_len = op;
    return out;
}

static unsigned char b64_inv[256];
static int b64_inv_inited = 0;
static void b64_inv_init(void)
{
    if (b64_inv_inited)
        return;
    for (int i = 0; i < 256; ++i)
        b64_inv[i] = 0xFF;
    for (int i = 0; i < 64; ++i)
    {
        b64_inv[(unsigned char)b64_table[i]] = (unsigned char)i;
    }
    b64_inv_inited = 1;
}

C_API unsigned char *base64_decode(const char *b64, size_t len, size_t *out_len)
{
    if (!b64)
    {
        if (out_len)
            *out_len = 0;
        return NULL;
    }
    b64_inv_init();

    if (len == 0)
        len = strlen(b64);

    if (len % 4 != 0)
    {
        if (out_len)
            *out_len = 0;
        return NULL;
    }

    size_t padding = 0;
    if (len >= 1 && b64[len - 1] == '=')
        ++padding;
    if (len >= 2 && b64[len - 2] == '=')
        ++padding;

    size_t out_size = (len / 4) * 3 - padding;
    unsigned char *out = (unsigned char *)malloc(out_size ? out_size : 1); /* avoid malloc(0) */
    if (!out)
    {
        if (out_len)
            *out_len = 0;
        return NULL;
    }

    size_t ip = 0, op = 0;
    while (ip < len)
    {
        unsigned char vals[4];
        for (int i = 0; i < 4; ++i)
        {
            unsigned char ch = (unsigned char)b64[ip++];
            if (ch == '=')
            {
                vals[i] = 0xFF;
            }
            else
            {
                unsigned char v = b64_inv[ch];
                if (v == 0xFF)
                {
                    free(out);
                    if (out_len)
                        *out_len = 0;
                    return NULL;
                }
                vals[i] = v;
            }
        }

        if (vals[0] == 0xFF || vals[1] == 0xFF)
        {
            free(out);
            if (out_len)
                *out_len = 0;
            return NULL;
        }

        uint32_t triple = ((uint32_t)vals[0] << 18) | ((uint32_t)vals[1] << 12);
        out[op++] = (unsigned char)((triple >> 16) & 0xFF);

        if (vals[2] != 0xFF)
        {
            triple |= ((uint32_t)vals[2] << 6);
            out[op++] = (unsigned char)((triple >> 8) & 0xFF);
            if (vals[3] != 0xFF)
            {
                triple |= ((uint32_t)vals[3]);
                out[op++] = (unsigned char)(triple & 0xFF);
            }
        }
    }

    if (op != out_size)
    {
    }
    if (out_len)
        *out_len = op;
    return out;
}