/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct bb_engine bb_engine;
typedef struct {
    uint64_t x[31], sp, pc, nzcv, tpidr_el0;
} bb_state;
typedef enum { BB_STOP, BB_BUDGET, BB_UNSUPPORTED, BB_MEMORY, BB_ALIGNMENT, BB_INTERNAL } bb_result;
enum { BB_R = 1, BB_W = 2, BB_X = 4 };
typedef struct { size_t native_blocks, interpreted_instructions, translations, evictions, invalidations; } bb_stats;
typedef bool (*bb_host_gate)(bb_state *state, void *opaque);
/* Single-threaded, sandboxed guest address range. Permissions are logical 4K guest pages. */
bb_engine *bb_create(const void *image, size_t size, size_t cache_slots);
/* Trusted, borrowed loader aliases and cache; caller owns both and serializes all
 * access. Cache must contain at least slots * 1024 bytes in both alias views. */
bb_engine *bb_attach(uint8_t *guest, uint8_t *write, size_t size, size_t slots,
                     uint8_t *cache_rw, uint8_t *cache_rx, size_t cache_size);
bool bb_set_host_gate(bb_engine *e, uint64_t address, bb_host_gate gate, void *opaque);
void bb_destroy(bb_engine *e);
uint64_t bb_base(const bb_engine *e);
bool bb_protect(bb_engine *e, size_t offset, size_t length, unsigned permissions);
bool bb_read(bb_engine *e, uint64_t guest, void *out, size_t length);
bool bb_write(bb_engine *e, uint64_t guest, const void *src, size_t length);
bb_result bb_run(bb_engine *e, bb_state *s, uint64_t stop_pc, size_t budget);
bb_stats bb_get_stats(const bb_engine *e);
const char *bb_result_name(bb_result r);
