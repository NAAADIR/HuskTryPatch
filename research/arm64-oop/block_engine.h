/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct bb_engine bb_engine;
typedef struct {
    uint64_t x[31], sp, pc, nzcv, tpidr_el0;
    uint64_t v[32][2]; /* 128-bit guest SIMD registers, low lane first */
    uint64_t exclusive_address, exclusive_generation;
    uint64_t exclusive_value;
    uint8_t exclusive_size;
    bool exclusive_valid;
} bb_state;
typedef enum { BB_STOP, BB_BUDGET, BB_UNSUPPORTED, BB_MEMORY, BB_ALIGNMENT, BB_INTERNAL } bb_result;
enum { BB_R = 1, BB_W = 2, BB_X = 4 };
typedef struct { size_t native_blocks, native_instructions, interpreted_instructions, translations, evictions, invalidations; } bb_stats;
typedef bool (*bb_host_gate)(bb_state *state, void *opaque);
/* Single-threaded, sandboxed guest address range. Permissions are logical 4K guest pages. */
bb_engine *bb_create(const void *image, size_t size, size_t cache_slots);
/* Trusted, borrowed loader aliases and cache; caller owns both and serializes all
 * access. Cache must contain at least slots * 1024 bytes in both alias views. */
bb_engine *bb_attach(uint8_t *guest, uint8_t *write, size_t size, size_t slots,
                     uint8_t *cache_rw, uint8_t *cache_rx, size_t cache_size);
/* Register distinct external targets. Lookup is by guest PC; callbacks and
 * execution are serialized by the caller. Clear removes all entries owned by
 * the given callback/opaque pair and must not race an active invocation. */
bool bb_set_host_gate(bb_engine *e, uint64_t address, bb_host_gate gate, void *opaque);
bool bb_clear_host_gate(bb_engine *e, bb_host_gate gate, void *opaque);
void bb_destroy(bb_engine *e);
/* Turn on the engine execution lock, once, before any thread enters the guest.
 * Guest instruction execution is then serialized per engine, while host gate
 * callbacks (where guest synchronization primitives actually block) run with
 * the lock released. Returns false if already running/threaded. */
bool bb_enable_threads(bb_engine *e);
uint64_t bb_base(const bb_engine *e);
bool bb_protect(bb_engine *e, size_t offset, size_t length, unsigned permissions);
bool bb_read(bb_engine *e, uint64_t guest, void *out, size_t length);
/* Check a whole guest range without dereferencing it. */
bool bb_access(bb_engine *e, uint64_t guest, size_t length, unsigned permissions);
bool bb_write(bb_engine *e, uint64_t guest, const void *src, size_t length);
/* Borrow a writable host alias only for guest-writable, non-executable pages.
 * The caller serializes access and must not retain it past the mapping. */
bool bb_host_data_alias(bb_engine *e, uint64_t guest, size_t length, void **out);
/* Serialized borrowed-domain heap. The arena must be page aligned, mapped RW,
 * and never executable; returned guest pointers never expose host pointers. */
bool bb_heap_init(bb_engine *e, size_t offset, size_t length);
uint64_t bb_heap_malloc(bb_engine *e, size_t size);
bool bb_heap_free(bb_engine *e, uint64_t guest);
bool bb_heap_realloc(bb_engine *e, uint64_t guest, size_t size, uint64_t *result);
bb_result bb_run(bb_engine *e, bb_state *s, uint64_t stop_pc, size_t budget);
#ifdef BB_TESTING
bb_result bb_run_reference(bb_engine *e, bb_state *s, uint64_t stop_pc, size_t budget);
#endif
bb_stats bb_get_stats(const bb_engine *e);
const char *bb_result_name(bb_result r);
