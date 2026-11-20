/* Stand-in for <linux/export.h>: user space has no kernel symbol table; the function is already global.
 *
 * Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
 */
#ifndef LINUX_COMPAT_LINUX_EXPORT_H
#define LINUX_COMPAT_LINUX_EXPORT_H
#define EXPORT_SYMBOL(sym)
#define EXPORT_SYMBOL_GPL(sym)
#endif
