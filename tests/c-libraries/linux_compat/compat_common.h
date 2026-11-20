/* Minimal layer to build the Linux kernel's lib/crypto/mldsa.c and lib/crypto/sha3.c in user space.
 * It is force-included (-include) before every kernel file and before the adapter.
 *
 * Only compiler attributes and configuration macros go here, with the same meaning as in the kernel
 * (include/linux/compiler_types.h, compiler_attributes.h, kconfig.h and build_bug.h). None of them touches the
 * arithmetic or the logic of verification. Behavioural substitutions: see linux/slab.h, linux/string.h and
 * linux/kernel.h (WARN_ON_ONCE).
 *
 * Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
 */
#ifndef LINUX_COMPAT_COMMON_H
#define LINUX_COMPAT_COMMON_H

#if !defined(__x86_64__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "This layer is meant for x86_64 (little-endian) only: the le*_to_cpu conversions are the identity"
#endif

/* Configuration: 64-bit kernel; no FIPS, no KUnit and no architecture-specific SHA-3 (the generic C code is used). */
#define CONFIG_64BIT 1
#ifndef KBUILD_MODNAME
#define KBUILD_MODNAME "compat"
#endif

/* IS_ENABLED(), as in include/linux/kconfig.h (without the _MODULE variant). */
#define __ARG_PLACEHOLDER_1 0,
#define __take_second_arg(__ignored, val, ...) val
#define __is_defined(x) ___is_defined(x)
#define ___is_defined(val) ____is_defined(__ARG_PLACEHOLDER_##val)
#define ____is_defined(arg1_or_junk) __take_second_arg(arg1_or_junk 1, 0)
#define IS_ENABLED(option) __is_defined(option)

/* Attributes. */
#define __always_inline inline __attribute__((__always_inline__))
#define noinline __attribute__((__noinline__))
#define __must_check __attribute__((__warn_unused_result__))
#define __maybe_unused __attribute__((__unused__))
#define __init
#define __exit
#define __initconst
#define __initdata

/* Error codes: in the kernel they come through <linux/errno.h> (included indirectly). The glibc ones on Linux
 * x86_64 have the same values (EINVAL 22, ENOMEM 12, EBADMSG 74, EKEYREJECTED 129). */
#include <errno.h>
#define __cleanup(func) __attribute__((__cleanup__(func)))

/* static_assert with one or two arguments, as in include/linux/build_bug.h. */
#undef static_assert
#define static_assert(expr, ...) __static_assert(expr, ##__VA_ARGS__, #expr)
#define __static_assert(expr, msg, ...) _Static_assert(expr, msg)

#endif
