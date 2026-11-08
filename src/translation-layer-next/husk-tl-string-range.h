/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef HUSK_TL_STRING_RANGE_H
#define HUSK_TL_STRING_RANGE_H
#include <stdbool.h>
#include <stdint.h>
static inline bool tl_string_range_valid(int32_t size, int32_t start, int32_t length)
{
    return size >= 0 && start >= 0 && length >= 0 && start <= size && length <= size - start;
}
#endif
