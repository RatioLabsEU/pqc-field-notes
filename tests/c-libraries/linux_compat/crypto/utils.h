/* Stand-in for <crypto/utils.h> with the only function lib/crypto/sha3.c uses: crypto_xor(dst, src, n),
 * dst[i] ^= src[i] for i < n (the kernel does the same operation, only word by word when it can).
 *
 * Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
 */
#ifndef LINUX_COMPAT_CRYPTO_UTILS_H
#define LINUX_COMPAT_CRYPTO_UTILS_H
#include <linux/types.h>

static inline void crypto_xor(u8* dst, const u8* src, unsigned int size)
{
    for (unsigned int i = 0; i < size; i++) dst[i] ^= src[i];
}
#endif
