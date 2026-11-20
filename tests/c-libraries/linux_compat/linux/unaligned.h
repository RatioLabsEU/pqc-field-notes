/* Stand-in for <linux/unaligned.h>: unaligned reads with memcpy (on x86_64 the kernel does the same, a normal load)
 * and, being little-endian, get_unaligned_leN reads the integer as it is.
 *
 * Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
 */
#ifndef LINUX_COMPAT_LINUX_UNALIGNED_H
#define LINUX_COMPAT_LINUX_UNALIGNED_H
#include <string.h>
#include <linux/types.h>

#define get_unaligned(p) ({ __typeof__(*(p)) _v; memcpy(&_v, (p), sizeof(_v)); _v; })

static inline u16 get_unaligned_le16(const void* p) { u16 v; memcpy(&v, p, 2); return v; }
static inline u32 get_unaligned_le32(const void* p) { u32 v; memcpy(&v, p, 4); return v; }
static inline u64 get_unaligned_le64(const void* p) { u64 v; memcpy(&v, p, 8); return v; }
#endif
