/* Stand-in for <linux/module.h>: empty module metadata. subsys_initcall and module_exit only appear inside
 * #ifdef CONFIG_CRYPTO_FIPS (FIPS self-tests), which is not defined here; they are left empty just in case.
 *
 * Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
 */
#ifndef LINUX_COMPAT_LINUX_MODULE_H
#define LINUX_COMPAT_LINUX_MODULE_H
#define MODULE_DESCRIPTION(x)
#define MODULE_LICENSE(x)
#define subsys_initcall(fn)
#define module_exit(fn)
#endif
