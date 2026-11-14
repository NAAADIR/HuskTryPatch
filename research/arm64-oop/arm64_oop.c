/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "arm64_oop.h"
#include <mach/mach.h>
#include <mach/mach_vm.h>

#include <libkern/OSCacheControl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#define MAX_INSNS 64
#define MAX_WORDS 32768
#define MAX_FIXUPS 8192
struct fixup { size_t at, target; unsigned bits; };
struct oop_ctx {
    uint8_t *guest, *rx, *rw;
    size_t image_size, guest_map_size, code_offset, code_size, cache_size, n, nf;
    uintptr_t tls;
    bool valid, poisoned;
    const char *error;
    uint32_t words[MAX_WORDS];
    size_t map[MAX_INSNS + 1];
    struct fixup fixes[MAX_FIXUPS];
};
static bool emit(oop_ctx *c, uint32_t w) {
    if (c->n == MAX_WORDS) { c->error = "cache staging overflow"; return false; }
    c->words[c->n++] = w; return true;
}
static bool imm64(oop_ctx *c, unsigned r, uint64_t v) {
    for (unsigned i = 0; i < 4; ++i)
        if (!emit(c, (i ? 0xf2800000u : 0xd2800000u) | (i << 21) | ((uint32_t)((v >> (i * 16)) & 0xffff) << 5) | r)) return false;
    return true;
}
static int64_t sx(uint64_t v, unsigned bits) { return (int64_t)(v ^ (1ULL << (bits-1))) - (int64_t)(1ULL << (bits-1)); }
static bool reg_ok(unsigned r) { return r <= 15 || r == 25 || r == 30; }
static bool fix(oop_ctx *c, uint32_t op, size_t target, unsigned bits) {
    if (c->nf == MAX_FIXUPS) { c->error = "too many branches"; return false; }
    c->fixes[c->nf++] = (struct fixup){c->n, target, bits}; return emit(c, op);
}
static bool target(oop_ctx *c, size_t i, int64_t delta, size_t *out) {
    int64_t p = (int64_t)(i * 4) + delta;
    if (p < 0 || (uint64_t)p >= c->code_size || (p & 3)) { c->error = "branch outside guest code"; return false; }
    *out = (size_t)p / 4; return true;
}
static bool ret_dispatch(oop_ctx *c) {
    /* x16/x17 are reserved. Preserve guest NZCV while resolving guest LR. */
    if (!emit(c, 0xd53b4211)) return false;
    for (size_t j = 0; j <= c->code_size / 4; ++j) {
        if (!imm64(c, 16, (uintptr_t)c->guest + c->code_offset + j * 4) ||
            !emit(c, 0xeb1003df) || !emit(c, 0x54000061) ||
            !emit(c, 0xd51b4211) || !fix(c, 0x14000000, j, 26)) return false;
    }
    return emit(c, 0xd51b4211) && emit(c, 0x92800000) && fix(c, 0x14000000, c->code_size / 4, 26);
}
static bool one(oop_ctx *c, size_t i, uint32_t w) {
    unsigned rd = w & 31, rn = (w >> 5) & 31;
    uintptr_t pc = (uintptr_t)c->guest + c->code_offset + i * 4;
    size_t t;
    if ((w & 0x9f000000) == 0x10000000 || (w & 0x9f000000) == 0x90000000) {
        if (!reg_ok(rd)) goto unsupported;
        int64_t d = sx(((w >> 5) & 0x7ffff) * 4ULL + ((w >> 29) & 3), 21);
        uint64_t address = (w & 0x80000000) ? (pc & ~(uintptr_t)4095) + d * 4096 : pc + d;
        return imm64(c, rd, address);
    }
    if ((w & 0xff000000) == 0x18000000 || (w & 0xff000000) == 0x58000000) {
        if (!reg_ok(rd)) goto unsupported;
        int64_t off = (int64_t)c->code_offset + (int64_t)i * 4 + sx((w >> 5) & 0x7ffff, 19) * 4;
        size_t sz = (w & 0x40000000) ? 8 : 4;
        if (off < 0 || (uint64_t)off > c->image_size || sz > c->image_size - (size_t)off) { c->error = "literal outside guest image"; return false; }
        return imm64(c, 16, (uintptr_t)c->guest + (size_t)off) && emit(c, (sz == 8 ? 0xf9400000 : 0xb9400000) | (16 << 5) | rd);
    }
    if ((w & 0x7c000000) == 0x14000000) {
        if (!target(c, i, sx(w & 0x3ffffff, 26) * 4, &t)) return false;
        if ((w & 0x80000000) && !imm64(c, 30, pc + 4)) return false;
        return fix(c, 0x14000000, t, 26);
    }
    if ((w & 0xff000010) == 0x54000000) {
        if (!target(c, i, sx((w >> 5) & 0x7ffff, 19) * 4, &t)) return false;
        return fix(c, w & ~(0x7ffffu << 5), t, 19);
    }
    if ((w & 0x7e000000) == 0x34000000 || (w & 0x7e000000) == 0x36000000) {
        if (!reg_ok(rd)) goto unsupported;
        unsigned bits = (w & 0x02000000) ? 14 : 19;
        uint32_t mask = (1u << bits) - 1;
        if (!target(c, i, sx((w >> 5) & mask, bits) * 4, &t)) return false;
        return fix(c, w & ~(mask << 5), t, bits);
    }
    if (w == 0xd65f03c0) return ret_dispatch(c);
    if ((w & 0xffffffe0) == 0xd53bd040 && reg_ok(rd)) return imm64(c, rd, c->tls);
    if (w == 0xd503201f) return emit(c, w);
    if ((w & 0xffe0ffe0) == 0xaa0003e0 && reg_ok(rd) && reg_ok((w >> 16) & 31)) return emit(c, w);
    if (((w & 0x7f800000) == 0x52800000 || (w & 0x7f800000) == 0x72800000) && reg_ok(rd) && ((w & 0x80000000) || !(w & 0x00400000))) return emit(c, w);
    if ((w & 0x1f800000) == 0x11000000 && reg_ok(rn) && (reg_ok(rd) || (rd == 31 && (w & 0x20000000)))) return emit(c, w);
    if (((w & 0xffc00000) == 0xb9400000 || (w & 0xffc00000) == 0xf9400000) && reg_ok(rd) && reg_ok(rn)) return emit(c, w);
unsupported:
    c->error = "unsupported instruction or reserved register"; return false;
}

oop_ctx *oop_create_at(const void *image, size_t size, size_t offset, size_t code, uintptr_t tls) {
    long page = sysconf(_SC_PAGESIZE);
    if (!image || page <= 0 || !size || size > INT64_MAX || !code || (offset & 3) || (code & 3) || offset > size || code > size - offset || code / 4 > MAX_INSNS || size > SIZE_MAX - (size_t)page) return NULL;
    oop_ctx *c = calloc(1, sizeof(*c)); if (!c) return NULL;
    c->guest_map_size = (size + (size_t)page - 1) / (size_t)page * (size_t)page;
    c->cache_size = (MAX_WORDS * 4 + (size_t)page - 1) / (size_t)page * (size_t)page;
    c->image_size = size; c->code_offset = offset; c->code_size = code; c->tls = tls;
    c->guest = mmap(NULL, c->guest_map_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (c->guest == MAP_FAILED) { c->guest = NULL; goto fail; }
    memcpy(c->guest, image, size);
    if (mprotect(c->guest, c->guest_map_size, PROT_READ)) goto fail;
    c->rw = mmap(NULL, c->cache_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (c->rw == MAP_FAILED) { c->rw = NULL; goto fail; }
    mach_vm_address_t dest = 0; vm_prot_t cur, max;
    if (mach_vm_remap(mach_task_self(), &dest, c->cache_size, 0, VM_FLAGS_ANYWHERE, mach_task_self(), (mach_vm_address_t)c->rw, FALSE, &cur, &max, VM_INHERIT_NONE) != KERN_SUCCESS) goto fail;
    c->rx = (uint8_t *)dest;
    if (mprotect(c->rx, c->cache_size, PROT_READ | PROT_EXEC)) goto fail;
    return c;
fail: oop_destroy(c); return NULL;
}
oop_ctx *oop_create(const void *image, size_t size, size_t code, uintptr_t tls) { return oop_create_at(image, size, 0, code, tls); }
void oop_destroy(oop_ctx *c) { if (!c) return; if (c->rx) munmap(c->rx, c->cache_size); if (c->rw) munmap(c->rw, c->cache_size); if (c->guest) munmap(c->guest, c->guest_map_size); free(c); }
bool oop_translate(oop_ctx *c) {
    if (!c) return false;
    if (c->poisoned) { c->error = "guest memory protection failed"; return false; }
    c->valid = false; c->error = NULL; c->n = c->nf = 0;
    if (!emit(c, 0xa9bf7bf9) || !imm64(c, 30, (uintptr_t)c->guest + c->code_offset + c->code_size)) return false;
    for (size_t i = 0; i < c->code_size / 4; ++i) {
        uint32_t w; memcpy(&w, c->guest + c->code_offset + 4*i, 4); c->map[i] = c->n;
        if (!one(c, i, w)) return false;
    }
    c->map[c->code_size / 4] = c->n;
    if (!emit(c, 0xa8c17bf9) || !emit(c, 0xd65f03c0)) return false;
    for (size_t i = 0; i < c->nf; ++i) {
        struct fixup f = c->fixes[i]; int64_t d = (int64_t)c->map[f.target] - (int64_t)f.at;
        if (d < -(1LL << (f.bits-1)) || d >= (1LL << (f.bits-1))) { c->error = "translated branch out of range"; return false; }
        uint32_t mask = (1u << f.bits) - 1;
        c->words[f.at] |= ((uint32_t)d & mask) << (f.bits == 26 ? 0 : 5);
    }
    memcpy(c->rw, c->words, c->n * 4); sys_icache_invalidate(c->rx, c->n * 4); c->valid = true; return true;
}
bool oop_run(oop_ctx *c, uint64_t *result) {
    if (!c || !result || !c->valid) return false;
    uint64_t v = ((uint64_t (*)(void))(void *)c->rx)();
    if (v == UINT64_MAX) { c->error = "unknown guest return address"; return false; }
    *result = v; return true;
}
bool oop_write(oop_ctx *c, size_t off, const void *src, size_t len) {
    if (!c || c->poisoned || (!src && len) || off > c->image_size || len > c->image_size - off) return false;
    if (!len) return true;
    c->valid = false;
    if (mprotect(c->guest, c->guest_map_size, PROT_READ | PROT_WRITE)) { c->error = "guest mprotect write failed"; return false; }
    memmove(c->guest + off, src, len);
    if (mprotect(c->guest, c->guest_map_size, PROT_READ)) { c->poisoned = true; c->error = "guest mprotect read failed"; return false; }
    return true;
}
const uint8_t *oop_guest(const oop_ctx *c) { return c->guest; }
const uint8_t *oop_cache(const oop_ctx *c) { return c->rx; }
const char *oop_error(const oop_ctx *c) { return c->error ? c->error : "none"; }
