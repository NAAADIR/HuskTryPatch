/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef HUSK_TL_RENDER_DIAG_H
#define HUSK_TL_RENDER_DIAG_H

/* Sparse checkpoints keep GPU readback out of the normal frame loop. */
static inline int tl_diag_sample_frame(unsigned long frame)
{
    return frame == 1 || frame == 120 || frame == 600 || frame == 1800 || frame == 3000;
}

static inline int tl_diag_points(int w, int h, int p[5][2])
{
    if (w <= 0 || h <= 0) return 0;
    p[0][0] = w / 2; p[0][1] = h / 2;
    p[1][0] = w / 4; p[1][1] = h / 4;
    p[2][0] = (w - 1) - w / 4; p[2][1] = h / 4;
    p[3][0] = w / 4; p[3][1] = (h - 1) - h / 4;
    p[4][0] = (w - 1) - w / 4; p[4][1] = (h - 1) - h / 4;
    return 1;
}
#endif
