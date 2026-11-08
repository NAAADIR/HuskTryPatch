/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef HUSK_TL_WEB_RECT_H
#define HUSK_TL_WEB_RECT_H
#include <stdbool.h>
#include <stdint.h>

/* Android top-left pixel coordinates to a clipped OpenGL scissor. */
static inline bool tl_web_scissor(int x, int y, int w, int h, int vw, int vh, int out[4])
{
    int64_t l = x, t = y, r = (int64_t)x + w, b = (int64_t)y + h;
    if (w <= 0 || h <= 0 || vw <= 0 || vh <= 0) return false;
    if (l < 0) l = 0; if (t < 0) t = 0;
    if (r > vw) r = vw; if (b > vh) b = vh;
    if (r <= l || b <= t) return false;
    out[0] = (int)l; out[1] = vh - (int)b; out[2] = (int)(r-l); out[3] = (int)(b-t);
    return true;
}
#endif
