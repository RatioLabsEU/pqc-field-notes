/* Stand-in for <linux/slab.h> and for the part of <linux/cleanup.h> that mldsa.c uses.
 *   kmalloc(n, GFP_KERNEL) -> malloc of n bytes plus a 16-byte header that stores n (returns NULL on failure, like
 *                             kmalloc; mldsa.c handles it with -ENOMEM). The memory is 16-byte aligned.
 *   kfree_sensitive(p)     -> wipes the n requested bytes (in the kernel, ksize(p) bytes) and frees.
 *                             malloc_usable_size is not used: with _FORTIFY_SOURCE=3, wiping more than was requested
 *                             aborts ("buffer overflow detected"), and that would be a fault of this layer, not of
 *                             the kernel.
 *   __free(kfree_sensitive) -> cleanup attribute that calls kfree_sensitive when leaving the scope, like
 *                             DEFINE_FREE(kfree_sensitive, void *, if (_T) kfree_sensitive(_T)) in slab.h.
 *
 * Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
 */
#ifndef LINUX_COMPAT_LINUX_SLAB_H
#define LINUX_COMPAT_LINUX_SLAB_H
#include <stdlib.h>
#include <string.h>

#define GFP_KERNEL 0
static inline void* kmalloc(size_t n, int flags)
{
    unsigned char* b;
    (void)flags;
    b = malloc(16 + n);
    if (b == NULL) return NULL;
    memcpy(b, &n, sizeof(n));
    return b + 16;
}
static inline void kfree_sensitive(const void* p)
{
    unsigned char* b;
    size_t n;
    if (p == NULL) return;
    b = (unsigned char*)p - 16;
    memcpy(&n, b, sizeof(n));
    explicit_bzero((void*)p, n);
    free(b);
}

#define __free(_name) __cleanup(__free_##_name)
static inline void __free_kfree_sensitive(void* p)
{
    void* _T = *(void**)p;
    if (_T) kfree_sensitive(_T);
}
#endif
