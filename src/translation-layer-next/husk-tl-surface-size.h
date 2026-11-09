/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef HUSK_TL_SURFACE_SIZE_H
#define HUSK_TL_SURFACE_SIZE_H
#include <stdint.h>
#include <stdatomic.h>
typedef _Atomic(uint64_t) tl_surface_size;
static inline uint64_t tl_surface_pack(int w, int h) { return ((uint64_t)(uint32_t)w << 32) | (uint32_t)h; }
static inline void tl_surface_load(const tl_surface_size *s, int *w, int *h) {
    uint64_t v = atomic_load_explicit(s, memory_order_acquire);
    *w = (int)(v >> 32); *h = (int)(uint32_t)v;
}
static inline int tl_surface_update(tl_surface_size *s, int w, int h) {
    if (w <= 0 || h <= 0) return 0;
    uint64_t v = tl_surface_pack(w, h);
    return atomic_exchange_explicit(s, v, memory_order_acq_rel) != v;
}
#endif
