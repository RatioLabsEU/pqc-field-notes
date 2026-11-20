/* Stand-in for <linux/string.h>: memcpy/memcmp/memset from libc, plus the two kernel functions that are used.
 *   memzero_explicit  -> glibc's explicit_bzero (same purpose: the compiler must not remove the wipe).
 *   mem_is_zero       -> loop equivalent to lib/string.c (returns true if the n bytes are zero; n = 0 gives true).
 *
 * Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
 */
#ifndef LINUX_COMPAT_LINUX_STRING_H
#define LINUX_COMPAT_LINUX_STRING_H
#include <string.h>
#include <linux/types.h>

static inline void memzero_explicit(void* s, size_t n) { explicit_bzero(s, n); }

static inline bool mem_is_zero(const void* s, size_t n)
{
    const u8* p = s;
    for (size_t i = 0; i < n; i++)
        if (p[i] != 0) return false;
    return true;
}
#endif
