/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef HUSK_TL_CURRENT_H
#define HUSK_TL_CURRENT_H
#include <stdbool.h>
#include <stdatomic.h>
typedef unsigned (*tl_make_current_fn)(void *, void *, void *, void *);
static inline bool tl_checked_current(tl_make_current_fn fn, void *display, void *surface, void *context, atomic_bool *ended) {
    if (fn && fn(display, surface, surface, context)) return true;
    atomic_store(ended, true);
    return false;
}
#endif
