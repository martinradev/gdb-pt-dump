#pragma once

#include <stddef.h>

void memset(volatile unsigned char *buf, int v, size_t sz)
{
    for (size_t i = 0; i < sz; ++i) {
        buf[i] = v;
    }
}

void memcpy(volatile unsigned char *buf, volatile unsigned char *src, size_t sz)
{
    for (size_t i = 0; i < sz; ++i) {
        buf[i] = src[i];
    }
}

size_t strlen(volatile unsigned char *buf)
{
    size_t i = 0;
    while (buf[i++]);
    return i - 1;
}

int strcmp(const char *left, const char *right)
{
    while (1) {
        char l = *left;
        char r = *right;
        if (l != r) {
            return (int)l - (int)r;
        }
        if (l == 0) {
            break;
        }
    }
    return 0;
}

void write_to_addresses(void *addresses[], size_t n, void *value, size_t value_size)
{
    for (size_t i = 0; i < n; ++i) {
        volatile void *ptr = addresses[i];
        memcpy(ptr, value, value_size);
    }
    memset(value, 0, value_size);
}
