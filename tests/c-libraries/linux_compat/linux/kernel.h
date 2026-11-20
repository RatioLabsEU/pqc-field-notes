/* Stand-in for <linux/kernel.h> with what lib/crypto/sha3.c uses: min, ARRAY_SIZE, rol64 and WARN_ON_ONCE.
 * WARN_ON_ONCE writes a warning to stderr the first time (in the kernel it would be a WARN in dmesg) and returns the
 * condition; so if it ever fires, it shows up in the log.
 *
 * Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
 */
#ifndef LINUX_COMPAT_LINUX_KERNEL_H
#define LINUX_COMPAT_LINUX_KERNEL_H
#include <stdio.h>
#include <linux/types.h>

#define min(a, b) ({ __auto_type _a = (a); __auto_type _b = (b); _a < _b ? _a : _b; })
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
static inline u64 rol64(u64 w, unsigned int s) { return (w << (s & 63)) | (w >> ((-s) & 63)); }

#define WARN_ON_ONCE(cond) ({ static int _done; int _c = !!(cond); \
    if (_c && !_done) { _done = 1; fprintf(stderr, "WARN_ON_ONCE: %s:%d %s\n", __FILE__, __LINE__, #cond); } _c; })
#endif
