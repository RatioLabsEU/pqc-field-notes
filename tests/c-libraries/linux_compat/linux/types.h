/* Stand-in for <linux/types.h> and for the byte-order conversions (byteorder/little_endian.h):
 * C99 fixed-width types and, since x86_64 is little-endian, le<->cpu conversions that are the identity.
 *
 * Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
 */
#ifndef LINUX_COMPAT_LINUX_TYPES_H
#define LINUX_COMPAT_LINUX_TYPES_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;
typedef uint16_t __le16;
typedef uint32_t __le32;
typedef uint64_t __le64;

#define cpu_to_le16(x) ((__le16)(u16)(x))
#define le16_to_cpu(x) ((u16)(__le16)(x))
#define cpu_to_le32(x) ((__le32)(u32)(x))
#define le32_to_cpu(x) ((u32)(__le32)(x))
#define cpu_to_le64(x) ((__le64)(u64)(x))
#define le64_to_cpu(x) ((u64)(__le64)(x))
#define le64_to_cpus(p) ((void)(p))
#endif
