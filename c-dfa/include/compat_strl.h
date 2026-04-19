#ifndef COMPAT_STRL_H
#define COMPAT_STRL_H

#include <string.h>

static inline size_t compat_strlcpy(char *dst, const char *src, size_t size)
{
    size_t slen = strlen(src);
    if (size > 0) {
        size_t copy = slen < size - 1 ? slen : size - 1;
        memcpy(dst, src, copy);
        dst[copy] = '\0';
    }
    return slen;
}

static inline size_t compat_strlcat(char *dst, const char *src, size_t size)
{
    size_t dlen = strnlen(dst, size);
    if (dlen >= size) return size + strlen(src);
    return dlen + compat_strlcpy(dst + dlen, src, size - dlen);
}

#define strlcpy compat_strlcpy
#define strlcat compat_strlcat

#endif
