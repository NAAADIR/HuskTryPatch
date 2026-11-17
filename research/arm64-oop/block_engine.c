/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Research only. No production loader, host calls, threads or signal emulation. */
#include "block_engine.h"
#include <TargetConditionals.h>
#include <mach/mach.h>
#if TARGET_OS_OSX
#include <mach/mach_vm.h>
#endif
#include <libkern/OSCacheControl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <pthread.h>

#define GPAGE 4096u
#define SLOT 1024u
#define MAX_BLOCK 16u
#define MAX_SLOTS 64u
#define MAX_HOST_GATES 8192u
struct block { uint64_t pc; uint8_t count; bool valid, native, control, simd; };
struct host_gate { uint64_t address; bb_host_gate gate; void *opaque; };
struct heap_block { size_t off, size, reserved; struct heap_block *next; };
struct bb_engine {
    uint8_t *guest, *perms, *rw, *rx;
    uint8_t *guest_write;
    size_t size, map_size, npages, cache_size, slots, next;
    struct block blocks[MAX_SLOTS];
    bb_stats stats;
    bool poisoned;
    bool borrowed;
    struct host_gate *gates;
    size_t gate_count, gate_capacity;
    uint64_t write_generation;
    size_t heap_off, heap_size;
    struct heap_block *heap;
    struct heap_block *heap_cache[256];   /* recent range() hits by 4 KiB page; cleared on free */
    /* Guest instruction execution and every mutation of the cache, heap,
     * permissions and gate table are serialized by this lock. bb_run holds it
     * while translating and running blocks, and releases it only across a host
     * gate callback, so a guest thread blocking in a host synchronization
     * primitive (pthread_mutex_lock, cond_wait) never holds it and cannot
     * deadlock another guest thread. See tl_oop_thread policy note. */
    pthread_mutex_t lock;
    bool threaded;
};
static void engine_lock(bb_engine *e) { if (e->threaded) pthread_mutex_lock(&e->lock); }
static void engine_unlock(bb_engine *e) { if (e->threaded) pthread_mutex_unlock(&e->lock); }
static bool set_host_gate_locked(bb_engine *e, uint64_t address, bb_host_gate gate, void *opaque);
static bool clear_host_gate_locked(bb_engine *e, bb_host_gate gate, void *opaque);
static int64_t sext(uint64_t v, unsigned n) { return (int64_t)(v ^ (UINT64_C(1) << (n-1))) - (int64_t)(UINT64_C(1) << (n-1)); }
static bool range(bb_engine *e, uint64_t a, size_t n, unsigned perm, size_t *off) {
    uint64_t base = (uintptr_t)e->guest;
    if (e->poisoned || a < base || a - base > e->size || n > e->size - (size_t)(a - base)) return false;
    size_t p = (size_t)(a - base);
    if (n && e->heap_size && p<e->heap_off+e->heap_size && p+n>e->heap_off) {
        if ((perm&BB_X) || p<e->heap_off || p+n>e->heap_off+e->heap_size) return false;
        struct heap_block **slot=&e->heap_cache[(p/GPAGE)&255], *b=*slot;
        if (!b || p<b->off || p-b->off>=b->size) {
            b=e->heap;
            while (b && (p<b->off || p-b->off>=b->size)) b=b->next;
            if (b) *slot=b;
        }
        if (!b || n>b->size-(p-b->off)) return false;
    }
    if (n) for (size_t i = p / GPAGE; i <= (p + n - 1) / GPAGE; ++i) if ((e->perms[i] & perm) != perm) return false;
    if (off) *off = p;
    return true;
}
static void invalidate(bb_engine *e) {
    bool any = false;
    for (size_t i = 0; i < e->slots; ++i) if (e->blocks[i].valid) { e->blocks[i].valid = false; any = true; }
    if (any) ++e->stats.invalidations;
}
bb_engine *bb_create(const void *image, size_t size, size_t slots) {
#if TARGET_OS_OSX
    long p = sysconf(_SC_PAGESIZE);
    if (!image || !size || p <= 0 || size > SIZE_MAX - (size_t)p || size > SIZE_MAX - GPAGE || !slots || slots > MAX_SLOTS) return NULL;
    bb_engine *e = calloc(1, sizeof(*e)); if (!e) return NULL;
    e->size = size; e->slots = slots; e->npages = (size + GPAGE - 1) / GPAGE;
    e->map_size = (size + (size_t)p - 1) / (size_t)p * (size_t)p;
    e->cache_size = (slots * SLOT + (size_t)p - 1) / (size_t)p * (size_t)p;
    e->perms = calloc(e->npages, 1); if (!e->perms) goto fail;
    e->guest = mmap(NULL, e->map_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (e->guest == MAP_FAILED) { e->guest = NULL; goto fail; }
    memcpy(e->guest, image, size);
    if (mprotect(e->guest, e->map_size, PROT_READ)) goto fail;
    e->rw = mmap(NULL, e->cache_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (e->rw == MAP_FAILED) { e->rw = NULL; goto fail; }
    mach_vm_address_t dest = 0; vm_prot_t cur, max;
    if (mach_vm_remap(mach_task_self(), &dest, e->cache_size, 0, VM_FLAGS_ANYWHERE, mach_task_self(), (mach_vm_address_t)e->rw, FALSE, &cur, &max, VM_INHERIT_NONE) != KERN_SUCCESS) goto fail;
    e->rx = (uint8_t *)dest;
    if (mprotect(e->rx, e->cache_size, PROT_READ | PROT_EXEC)) goto fail;
    return e;
fail: bb_destroy(e); return NULL;
#else
    /* Device tests borrow Husk's debugger-granted aliases via bb_attach. */
    (void)image; (void)size; (void)slots; return NULL;
#endif
}
static bool spans_overlap(uintptr_t a, size_t na, uintptr_t b, size_t nb) {
    return a<=b ? b-a<na : a-b<nb;
}
bb_engine *bb_attach(uint8_t *guest, uint8_t *write, size_t size, size_t slots, uint8_t *rw, uint8_t *rx, size_t cache_size) {
    if (!guest || !write || !size || size > SIZE_MAX - GPAGE || !slots || slots > MAX_SLOTS || !rw || !rx || rw == rx || cache_size < slots*SLOT) return NULL;
    uintptr_t g=(uintptr_t)guest, w=(uintptr_t)write, c=(uintptr_t)rw, x=(uintptr_t)rx;
    if (size-1>UINTPTR_MAX-g || size-1>UINTPTR_MAX-w || cache_size-1>UINTPTR_MAX-c || cache_size-1>UINTPTR_MAX-x ||
        spans_overlap(g,size,w,size) || spans_overlap(c,cache_size,x,cache_size) ||
        spans_overlap(g,size,c,cache_size) || spans_overlap(g,size,x,cache_size) ||
        spans_overlap(w,size,c,cache_size) || spans_overlap(w,size,x,cache_size)) return NULL;
    bb_engine *e=calloc(1,sizeof(*e)); if (!e) return NULL;
    e->size=size; e->slots=slots; e->npages=(size+GPAGE-1)/GPAGE;
    e->perms=calloc(e->npages,1); if (!e->perms) { free(e); return NULL; }
    e->guest=guest; e->guest_write=write; e->rw=rw; e->rx=rx; e->cache_size=cache_size; e->borrowed=true; return e;
}
bool bb_enable_threads(bb_engine *e) {
    if (!e || e->threaded || e->poisoned) return false;
    pthread_mutexattr_t a; pthread_mutexattr_init(&a);
    /* Recursive: the interpreter reaches the public bb_read/bb_write while the
     * run loop already holds the lock; a host gate callback reaches the same
     * API after the loop has released it. Both must be safe on this thread. */
    pthread_mutexattr_settype(&a, PTHREAD_MUTEX_RECURSIVE);
    bool ok = pthread_mutex_init(&e->lock, &a)==0;
    pthread_mutexattr_destroy(&a);
    if (ok) e->threaded=true;
    return ok;
}
bool bb_set_host_gate(bb_engine *e, uint64_t address, bb_host_gate gate, void *opaque) {
    if (!e) return false; engine_lock(e); bool r=set_host_gate_locked(e,address,gate,opaque); engine_unlock(e); return r;
}
static bool set_host_gate_locked(bb_engine *e, uint64_t address, bb_host_gate gate, void *opaque) {
    if (!e || !address || !gate || range(e,address,1,0,NULL) ||
        (e->guest_write && spans_overlap((uintptr_t)address,1,(uintptr_t)e->guest_write,e->size)) ||
        spans_overlap((uintptr_t)address,1,(uintptr_t)e->rw,e->cache_size) ||
        spans_overlap((uintptr_t)address,1,(uintptr_t)e->rx,e->cache_size)) return false;
    size_t lo=0,hi=e->gate_count;
    while (lo<hi) { size_t m=lo+(hi-lo)/2; if (e->gates[m].address<address) lo=m+1; else hi=m; }
    if ((lo<e->gate_count && e->gates[lo].address==address) || e->gate_count==MAX_HOST_GATES) return false;
    if (e->gate_count==e->gate_capacity) {
        size_t cap=e->gate_capacity ? e->gate_capacity*2 : 16;
        struct host_gate *p=realloc(e->gates,cap*sizeof(*p)); if (!p) return false;
        e->gates=p; e->gate_capacity=cap;
    }
    memmove(e->gates+lo+1,e->gates+lo,(e->gate_count-lo)*sizeof(*e->gates));
    e->gates[lo]=(struct host_gate){address,gate,opaque}; ++e->gate_count; return true;
}
bool bb_clear_host_gate(bb_engine *e, bb_host_gate gate, void *opaque) {
    if (!e) return false; engine_lock(e); bool r=clear_host_gate_locked(e,gate,opaque); engine_unlock(e); return r;
}
static bool clear_host_gate_locked(bb_engine *e, bb_host_gate gate, void *opaque) {
    if (!e || !gate) return false;
    size_t keep=0,old=e->gate_count;
    for (size_t i=0;i<old;i++)
        if (e->gates[i].gate!=gate || e->gates[i].opaque!=opaque) e->gates[keep++]=e->gates[i];
    e->gate_count=keep; return keep!=old;
}
void bb_destroy(bb_engine *e) { if (!e) return; if (e->threaded) pthread_mutex_destroy(&e->lock); while (e->heap) { struct heap_block *b=e->heap; e->heap=b->next; free(b); } if (!e->borrowed) { if (e->guest) munmap(e->guest, e->map_size); if (e->rw) munmap(e->rw, e->cache_size); if (e->rx) munmap(e->rx, e->cache_size); } free(e->gates); free(e->perms); free(e); }
uint64_t bb_base(const bb_engine *e) { return (uintptr_t)e->guest; }
static bool protect_u(bb_engine *e, size_t off, size_t len, unsigned p) {
    if (!e || e->poisoned || (p & ~(BB_R | BB_W | BB_X)) || !len || off % GPAGE || len % GPAGE || off > e->npages * GPAGE || len > e->npages * GPAGE - off) return false;
    if (e->heap_size && off<e->heap_off+e->heap_size && e->heap_off<off+len) return false;
    invalidate(e); for (size_t i = off / GPAGE; i < (off + len) / GPAGE; ++i) e->perms[i] = (uint8_t)p;
    ++e->write_generation; return true;
}
static bool heap_init_u(bb_engine *e, size_t off, size_t len) {
    if (!e || !e->borrowed || e->heap_size || !len || (off%GPAGE) || (len%GPAGE) ||
        off>e->size || len>e->size-off) return false;
    for (size_t i=off/GPAGE;i<(off+len)/GPAGE;i++) if (e->perms[i]) return false;
    if (!protect_u(e,off,len,BB_R|BB_W)) return false;
    e->heap_off=off; e->heap_size=len; return true;
}
static uint64_t heap_malloc_u(bb_engine *e, size_t n) {
    if (!e || !e->heap_size || e->poisoned) return 0;
    if (!n) n=1;
    if (n>SIZE_MAX-15) return 0;
    size_t reserved=(n+15)&~(size_t)15, off=e->heap_off, end=off+e->heap_size;
    struct heap_block **link=&e->heap;
    while (*link) {
        struct heap_block *b=*link;
        if (off<=b->off && reserved<=b->off-off) break;
        off=b->off+b->reserved; link=&b->next;
    }
    if (off>end || reserved>end-off) return 0;
    struct heap_block *b=malloc(sizeof(*b)); if (!b) return 0;
    *b=(struct heap_block){off,n,reserved,*link}; *link=b;
    ++e->write_generation; return (uintptr_t)e->guest+off;
}
static bool heap_free_u(bb_engine *e, uint64_t guest) {
    if (!guest) return e && e->heap_size && !e->poisoned;
    if (!e || !e->heap_size || e->poisoned || guest<(uintptr_t)e->guest) return false;
    uint64_t off=guest-(uintptr_t)e->guest; struct heap_block **link=&e->heap;
    while (*link && (*link)->off!=off) link=&(*link)->next;
    if (!*link) return false;
    struct heap_block *b=*link; *link=b->next;
    for (size_t i=0;i<256;i++) if (e->heap_cache[i]==b) e->heap_cache[i]=NULL;
    free(b); ++e->write_generation; return true;
}
static bool heap_realloc_u(bb_engine *e, uint64_t guest, size_t n, uint64_t *result) {
    if (!e || !result || !e->heap_size || e->poisoned) return false;
    if (!guest) { *result=heap_malloc_u(e,n); return true; }
    struct heap_block *b=e->heap; uint64_t base=(uintptr_t)e->guest;
    while (b && (guest<base || b->off!=guest-base)) b=b->next;
    if (!b) return false;
    if (!n) { if (!heap_free_u(e,guest)) return false; *result=0; return true; }
    if (n<=b->reserved) { b->size=n; ++e->write_generation; *result=guest; return true; }
    uint64_t replacement=heap_malloc_u(e,n);
    if (!replacement) { *result=0; return true; }
    size_t off=(size_t)(replacement-base), old=b->off, count=b->size;
    memmove(e->guest_write+off,e->guest_write+old,count);
    ++e->write_generation;
    if (!heap_free_u(e,guest)) { e->poisoned=true; return false; }
    *result=replacement; return true;
}
static bool read_u(bb_engine *e, uint64_t a, void *out, size_t n) { size_t off; if (!e || (!out && n) || !range(e, a, n, BB_R, &off)) return false; if (n) memcpy(out, e->guest + off, n); return true; }
static bool access_u(bb_engine *e, uint64_t a, size_t n, unsigned p) {
    return e && !(p & ~(BB_R|BB_W|BB_X)) && range(e,a,n,p,NULL);
}
static bool alias_u(bb_engine *e, uint64_t a, size_t n, void **out) {
    size_t off;
    if (out) *out=NULL;
    if (!e || !out || !n || !e->borrowed || !e->guest_write ||
        !range(e,a,n,BB_R|BB_W,&off)) return false;
    for (size_t p=off/GPAGE;p<=(off+n-1)/GPAGE;p++) if (e->perms[p]&BB_X) return false;
    *out=e->guest_write+off; return true;
}
/* Translated blocks come only from executable logical pages: a write that
 * touches none of them cannot make a cached block stale. */
static bool touches_exec(const bb_engine *e, size_t off, size_t n) {
    for (size_t i=off/GPAGE;n && i<=(off+n-1)/GPAGE;++i) if (e->perms[i]&BB_X) return true;
    return false;
}
static bool write_u(bb_engine *e, uint64_t a, const void *src, size_t n) {
    size_t off; if (!e || (!src && n) || !range(e, a, n, BB_W, &off)) return false;
    if (!n) return true;
    if (e->borrowed) {
        /* Different virtual aliases may overlap physically; memmove cannot see it. */
        uintptr_t p=(uintptr_t)src, base=(uintptr_t)e->guest;
        if ((p>=base && p-base<e->size) || (p<base && n>base-p)) return false;
        if (touches_exec(e,off,n)) invalidate(e);
        memmove(e->guest_write+off,src,n); ++e->write_generation; return true;
    }
    /* All translated blocks are invalidated before any guest write. */
    invalidate(e);
    if (mprotect(e->guest, e->map_size, PROT_READ | PROT_WRITE)) return false;
    memmove(e->guest + off, src, n);
    if (mprotect(e->guest, e->map_size, PROT_READ)) { e->poisoned = true; return false; }
    ++e->write_generation;
    return true;
}
/* Public, thread-safe surface: the engine lock serializes every mutation of the
 * cache, heap, permissions and reads; the lock is recursive, so the interpreter
 * (which already holds it inside bb_run) and a host gate callback (which reaches
 * these after bb_run released it) are both correct. */
bool bb_protect(bb_engine *e, size_t off, size_t len, unsigned p) { if (!e) return false; engine_lock(e); bool r=protect_u(e,off,len,p); engine_unlock(e); return r; }
bool bb_heap_init(bb_engine *e, size_t off, size_t len) { if (!e) return false; engine_lock(e); bool r=heap_init_u(e,off,len); engine_unlock(e); return r; }
uint64_t bb_heap_malloc(bb_engine *e, size_t n) { if (!e) return 0; engine_lock(e); uint64_t r=heap_malloc_u(e,n); engine_unlock(e); return r; }
bool bb_heap_free(bb_engine *e, uint64_t guest) { if (!e) return false; engine_lock(e); bool r=heap_free_u(e,guest); engine_unlock(e); return r; }
bool bb_heap_realloc(bb_engine *e, uint64_t guest, size_t n, uint64_t *result) { if (!e) return false; engine_lock(e); bool r=heap_realloc_u(e,guest,n,result); engine_unlock(e); return r; }
bool bb_read(bb_engine *e, uint64_t a, void *out, size_t n) { if (!e) return false; engine_lock(e); bool r=read_u(e,a,out,n); engine_unlock(e); return r; }
bool bb_access(bb_engine *e, uint64_t a, size_t n, unsigned p) { if (!e) return false; engine_lock(e); bool r=access_u(e,a,n,p); engine_unlock(e); return r; }
bool bb_host_data_alias(bb_engine *e, uint64_t a, size_t n, void **out) { if (!e) { if (out) *out=NULL; return false; } engine_lock(e); bool r=alias_u(e,a,n,out); engine_unlock(e); return r; }
bool bb_write(bb_engine *e, uint64_t a, const void *src, size_t n) { if (!e) return false; engine_lock(e); bool r=write_u(e,a,src,n); engine_unlock(e); return r; }
bb_stats bb_get_stats(const bb_engine *e) { return e->stats; }
static uint64_t readreg(bb_state *s, unsigned r, bool sp) { return r == 31 ? (sp ? s->sp : 0) : s->x[r]; }
static void writereg(bb_state *s, unsigned r, bool sp, bool sf, uint64_t v) { if (!sf) v = (uint32_t)v; if (r != 31) s->x[r] = v; else if (sp) s->sp = v; }
static bool wide(uint32_t w) {
    uint32_t x = w & 0x7f800000;
    return (x == 0x52800000 || x == 0x72800000 || x == 0x12800000) && ((w & 0x80000000) || !(w & 0x00400000));
}
static bool fast(uint32_t w) {
    return wide(w) || (w & 0x1f000000) == 0x10000000 ||
        ((w & 0x1f800000) == 0x11000000 && !(w & 0x20000000)) || w == 0xd503201f;
}
/* These transfer guest PCs via the dispatcher, never directly to guest memory. */
static bool native_control(uint32_t w) {
    uint32_t op=w&0xfffffc1f;
    return (w&0x7c000000)==0x14000000 ||
        (((w>>5)&31)!=31 && (op==0xd61f0000 || op==0xd63f0000 || op==0xd65f0000));
}
static bool condition(unsigned c, uint64_t nzcv) {
    bool n = (nzcv >> 31) & 1, z = (nzcv >> 30) & 1, v = (nzcv >> 28) & 1, carry = (nzcv >> 29) & 1, b;
    switch (c >> 1) { case 0: b=z; break; case 1: b=carry; break; case 2: b=n; break; case 3: b=v; break; case 4: b=carry && !z; break; case 5: b=n==v; break; case 6: b=!z && n==v; break; default: b=true; break; }
    return (c & 1) && c != 15 ? !b : b;
}
static uint64_t flags(uint64_t a, uint64_t b, uint64_t r, bool sub, bool sf) {
    unsigned width = sf ? 64 : 32; uint64_t mask = sf ? UINT64_MAX : UINT32_MAX;
    a &= mask; b &= mask; r &= mask;
    bool n = (r >> (width-1)) & 1, z = !r;
    bool c = sub ? a >= b : r < a;
    bool v = sub ? (((a ^ b) & (a ^ r)) >> (width-1)) & 1 : ((~(a ^ b) & (a ^ r)) >> (width-1)) & 1;
    return ((uint64_t)n << 31) | ((uint64_t)z << 30) | ((uint64_t)c << 29) | ((uint64_t)v << 28);
}
/* ARM logical-immediate DecodeBitMasks, limited to the non-immediate-mask
 * form used by ANDS/TST. Reserved encodings are rejected. */
static bool logical_mask(uint32_t w, bool sf, uint64_t *out) {
    unsigned N=(w>>22)&1, immr=(w>>16)&63, imms=(w>>10)&63;
    if (!sf && N) return false;
    unsigned selector=(N<<6)|((~imms)&63), len=0;
    if (!selector) return false;
    for (unsigned t=selector;t>1;t>>=1) ++len;
    if (len<1 || (!sf && len>5) || len>6) return false;
    unsigned size=1u<<len, levels=size-1, S=imms&levels, R=immr&levels;
    if (S==levels) return false;
    uint64_t mask=size==64 ? UINT64_MAX : (UINT64_C(1)<<size)-1;
    uint64_t bits=(UINT64_C(1)<<(S+1))-1;
    if (R) bits=((bits>>R)|(bits<<(size-R)))&mask;
    uint64_t value=0; unsigned width=sf?64:32;
    for (unsigned shift=0;shift<width;shift+=size) value|=bits<<shift;
    *out=value; return true;
}
static bb_result step(bb_engine *e, bb_state *s, uint32_t w) {
    uint64_t pc=s->pc, next=pc+4, v, a; unsigned rd=w&31, rn=(w>>5)&31; bool sf=(w>>31)&1;
    if (wide(w)) {
        unsigned sh=((w>>21)&3)*16; uint64_t mask=UINT64_C(0xffff)<<sh, imm=(uint64_t)((w>>5)&0xffff)<<sh;
        uint32_t op=w&0x7f800000;
        v = op==0x72800000 ? (readreg(s,rd,false)&~mask)|imm : op==0x12800000 ? ~imm : imm;
        writereg(s,rd,false,sf,v);
    } else if ((w&0xfffffc00)==0x5ac00800 || (w&0xfffffc00)==0xdac00c00) {
        /* REV Wd,Wn / REV Xd,Xn. */
        v=readreg(s,rn,false);
        writereg(s,rd,false,sf,sf?__builtin_bswap64(v):__builtin_bswap32((uint32_t)v));
    } else if ((w&0x7fa00000)==0x13800000) {
        /* EXTR, including the ROR immediate alias. */
        unsigned width=sf?64:32, shift=(w>>10)&63, N=(w>>22)&1;
        if (N!=(unsigned)sf || shift>=width) return BB_UNSUPPORTED;
        uint64_t mask=sf?UINT64_MAX:UINT32_MAX, hi=readreg(s,rn,false)&mask;
        uint64_t lo=readreg(s,(w>>16)&31,false)&mask;
        v=shift ? (lo>>shift)|((hi<<(width-shift))&mask) : lo;
        writereg(s,rd,false,sf,v);
    } else if ((w&0x7f800000)==0x13000000) {
        /* SBFM ASR alias only; other signed bitfield forms fail closed. */
        unsigned N=(w>>22)&1, shift=(w>>16)&63, end=(w>>10)&63, width=sf?64:32;
        if (N!=(unsigned)sf || shift>=width || end!=width-1) return BB_UNSUPPORTED;
        uint64_t mask=sf?UINT64_MAX:UINT32_MAX, src=readreg(s,rn,false)&mask;
        v=shift ? (src>>shift)|((src>>(width-1)) ? (mask<<(width-shift))&mask : 0) : src;
        writereg(s,rd,false,sf,v);
    } else if ((w&0x7f800000)==0x53000000) {
        /* UBFM, including LSL/LSR and UBFX aliases. */
        unsigned N=(w>>22)&1, r=(w>>16)&63, end=(w>>10)&63, width=sf?64:32;
        if (N!=(unsigned)sf || r>=width || end>=width) return BB_UNSUPPORTED;
        uint64_t src=readreg(s,rn,false); if (!sf) src=(uint32_t)src;
        if (end>=r) {
            unsigned n=end-r+1; v=src>>r;
            if (n<64) v&=(UINT64_C(1)<<n)-1;
        } else {
            unsigned n=end+1; v=src&((UINT64_C(1)<<n)-1);
            v<<=width-r;
        }
        writereg(s,rd,false,sf,v);
    } else if ((w&0x7f800000)==0x72000000) {
        uint64_t mask;
        if (!logical_mask(w,sf,&mask)) return BB_UNSUPPORTED;
        v=readreg(s,rn,false)&mask; if (!sf) v=(uint32_t)v;
        s->nzcv=(v ? 0 : UINT64_C(1)<<30) | ((v>>(sf?63:31))<<31);
        writereg(s,rd,false,sf,v);
    } else if ((w&0x1f000000)==0x0a000000) {
        /* Logical shifted register, including BIC and all four shift kinds. */
        unsigned width=sf?64:32, shift=(w>>22)&3, amount=(w>>10)&63, opc=(w>>29)&3;
        if (amount>=width) return BB_UNSUPPORTED;
        uint64_t mask=sf?UINT64_MAX:UINT32_MAX;
        a=readreg(s,rn,false)&mask; v=readreg(s,(w>>16)&31,false)&mask;
        if (amount) {
            if (shift==0) v=(v<<amount)&mask;
            else if (shift==1) v>>=amount;
            else if (shift==2) v=(v>>amount)|((v>>(width-1))?(mask<<(width-amount))&mask:0);
            else v=((v>>amount)|(v<<(width-amount)))&mask;
        }
        if (w&(1u<<21)) v=(~v)&mask;
        v=opc==0 || opc==3 ? a&v : opc==1 ? a|v : a^v;
        if (opc==3) s->nzcv=(v?0:UINT64_C(1)<<30)|((v>>(width-1))<<31);
        writereg(s,rd,false,sf,v);
    } else if ((w&0x1f200000)==0x0b200000) {
        /* ADD/SUB extended register, including UXTW scaled addressing. */
        unsigned option=(w>>13)&7, shift=(w>>10)&7, bits=8u<<(option&3);
        bool sub=(w>>30)&1, set=(w>>29)&1;
        if (shift>4) return BB_UNSUPPORTED;
        v=readreg(s,(w>>16)&31,false);
        if (bits<64) { v&=(UINT64_C(1)<<bits)-1; if (option&4) v=(uint64_t)sext(v,bits); }
        v<<=shift; a=readreg(s,rn,true);
        uint64_t result=sub?a-v:a+v;
        if (set) s->nzcv=flags(a,v,result,sub,sf);
        writereg(s,rd,!set,sf,result);
    } else if ((w&0x1f200000)==0x0b000000) {
        /* ADD/SUB shifted register: XZR/WZR, never SP. */
        bool sub=(w>>30)&1, set=(w>>29)&1;
        unsigned shift=(w>>22)&3, amount=(w>>10)&63, width=sf?64:32;
        if (shift==3 || amount>=width) return BB_UNSUPPORTED;
        uint64_t mask=sf?UINT64_MAX:UINT32_MAX;
        a=readreg(s,rn,false)&mask; v=readreg(s,(w>>16)&31,false)&mask;
        if (amount) {
            if (shift==0) v=(v<<amount)&mask;
            else if (shift==1) v>>=amount;
            else v=(v>>amount)|((v>>(width-1)) ? (mask<<(width-amount))&mask : 0);
        }
        uint64_t result=sub?a-v:a+v;
        if (set) s->nzcv=flags(a,v,result,sub,sf);
        writereg(s,rd,false,sf,result);
    } else if ((w&0x1f800000)==0x12000000) {
        /* Logical immediates use a rotated run of ones replicated by element. */
        unsigned n=(w>>22)&1, imms=(w>>10)&63, immr=(w>>16)&63;
        unsigned encoded=(n<<6)|((~imms)&63), len=0;
        if (!encoded || (!sf && n)) return BB_UNSUPPORTED;
        for (unsigned t=encoded; t>>=1;) ++len;
        if (len<1 || (!sf && len>5)) return BB_UNSUPPORTED;
        unsigned levels=(1u<<len)-1, ones=imms&levels, rot=immr&levels;
        if (ones==levels) return BB_UNSUPPORTED;
        unsigned element=1u<<len, width=sf?64:32;
        uint64_t mask=element==64?UINT64_MAX:(UINT64_C(1)<<element)-1;
        uint64_t bits=(UINT64_C(1)<<(ones+1))-1;
        if (rot) bits=((bits>>rot)|(bits<<(element-rot)))&mask;
        uint64_t immediate=0; for (unsigned i=0;i<width;i+=element) immediate|=bits<<i;
        unsigned opc=(w>>29)&3; a=readreg(s,rn,false);
        v=opc==0 || opc==3 ? a&immediate : opc==1 ? a|immediate : a^immediate;
        if (!sf) v=(uint32_t)v;
        if (opc==3) s->nzcv=(v==0?0x40000000u:0) | ((v>>(width-1))?0x80000000u:0);
        writereg(s,rd,false,sf,v);
    } else if ((w&0x7fe00000)==0x1b000000) {
        /* MADD/MSUB W/X, including MUL/MNEG aliases. */
        uint64_t lhs=readreg(s,rn,false), rhs=readreg(s,(w>>16)&31,false), acc=readreg(s,(w>>10)&31,false);
        uint64_t product=lhs*rhs;
        v=(w&0x8000)?acc-product:acc+product;
        writereg(s,rd,false,sf,v);
    } else if ((w&0xffe00000)==0x9ba00000 || (w&0xffe00000)==0x9b200000) {
        /* UMADDL/UMSUBL and SMADDL/SMSUBL, including UMULL/SMULL. */
        uint32_t lhs=(uint32_t)readreg(s,rn,false), rhs=(uint32_t)readreg(s,(w>>16)&31,false);
        uint64_t product=(w&0x00800000)?(uint64_t)lhs*rhs:(uint64_t)((int64_t)(int32_t)lhs*(int64_t)(int32_t)rhs);
        uint64_t acc=readreg(s,(w>>10)&31,false);
        writereg(s,rd,false,true,(w&0x8000)?acc-product:acc+product);
    } else if ((w&0x3fe00800)==0x1a800000) {
        /* CSEL/CSINC/CSINV/CSNEG (including CSET and related aliases). */
        if (condition((w>>12)&15,s->nzcv)) v=readreg(s,rn,false);
        else {
            v=readreg(s,(w>>16)&31,false);
            if (w&(1u<<30)) v=~v;
            if (w&(1u<<10)) ++v;
        }
        writereg(s,rd,false,sf,v);
    } else if ((w&0x1f800000)==0x11000000) {
        bool sub=(w>>30)&1, set=(w>>29)&1; a=readreg(s,rn,true); v=(uint64_t)((w>>10)&0xfff)<<(((w>>22)&1)*12);
        uint64_t result=sub?a-v:a+v; if(set) s->nzcv=flags(a,v,result,sub,sf);
        writereg(s,rd,!set,sf,result);
    } else if ((w&0x9f000000)==0x10000000 || (w&0x9f000000)==0x90000000) {
        int64_t d=sext((((w>>5)&0x7ffff)*4ULL)+((w>>29)&3),21);
        v=(w&0x80000000)?(pc&~UINT64_C(4095))+(uint64_t)(d*4096):pc+(uint64_t)d; writereg(s,rd,false,true,v);
    } else if ((w&0x7fe0ffe0)==0x2a0003e0) {
        writereg(s,rd,false,sf,readreg(s,(w>>16)&31,false));
    } else if ((w&0x7c000000)==0x14000000) {
        if(w&0x80000000) s->x[30]=next; next=pc+(uint64_t)(sext(w&0x3ffffff,26)*4);
    } else if ((w&0xff000010)==0x54000000) {
        if(condition(w&15,s->nzcv)) next=pc+(uint64_t)(sext((w>>5)&0x7ffff,19)*4);
    } else if ((w&0x7e000000)==0x34000000) {
        v=readreg(s,rd,false); if(!sf) v=(uint32_t)v;
        if((v!=0)==((w>>24)&1)) next=pc+(uint64_t)(sext((w>>5)&0x7ffff,19)*4);
    } else if ((w&0x7e000000)==0x36000000) {
        unsigned bit=((w>>26)&32)|((w>>19)&31); v=readreg(s,rd,false);
        if(((v>>bit)&1)==((w>>24)&1)) next=pc+(uint64_t)(sext((w>>5)&0x3fff,14)*4);
    } else if ((w&0xfffffc1f)==0xd61f0000 || (w&0xfffffc1f)==0xd63f0000 || (w&0xfffffc1f)==0xd65f0000) {
        v=readreg(s,rn,false); if((w&0xfffffc1f)==0xd63f0000) s->x[30]=next; next=v;
    } else if ((w&0xff000000)==0x18000000 || (w&0xff000000)==0x58000000) {
        unsigned n=(w&0x40000000)?8:4; a=pc+(uint64_t)(sext((w>>5)&0x7ffff,19)*4); v=0;
        if (!read_u(e,a,&v,n)) return BB_MEMORY; writereg(s,rd,false,n==8,v);
    } else if ((w&0xbfff7c00)==0x885f7c00) {
        /* Serialized-domain LDXR/LDAXR W/X: reservations are per state. */
        size_t off,bytes=(w&0x40000000u)?8:4; a=readreg(s,rn,true);
        if (a&(bytes-1)) return BB_ALIGNMENT;
        if (!range(e,a,bytes,BB_R|BB_W,&off) || (e->perms[off/GPAGE]&BB_X)) return BB_MEMORY;
        int order=(w&0x8000)?__ATOMIC_ACQUIRE:__ATOMIC_RELAXED;
        uint64_t value=bytes==8 ? __atomic_load_n((const uint64_t *)(const void *)(e->guest+off),order)
                                : __atomic_load_n((const uint32_t *)(const void *)(e->guest+off),order);
        s->exclusive_address=a; s->exclusive_value=value; s->exclusive_size=(uint8_t)bytes;
        s->exclusive_generation=e->write_generation; s->exclusive_valid=true;
        writereg(s,rd,false,bytes==8,value);
    } else if ((w&0xbfe07c00)==0x88007c00) {
        /* STXR/STLXR Ws,Wt|Xt,[Xn]. A write or host transition invalidates the
         * reservation, which is a permitted spurious exclusive failure.
         * All access to the borrowed domain must remain serialized. */
        unsigned status=(w>>16)&31; size_t off,bytes=(w&0x40000000u)?8:4; a=readreg(s,rn,true);
        if (status!=31 && (status==rd || (rn!=31 && status==rn))) return BB_UNSUPPORTED;
        if (a&(bytes-1)) return BB_ALIGNMENT;
        if (!range(e,a,bytes,BB_R|BB_W,&off) || (e->perms[off/GPAGE]&BB_X)) return BB_MEMORY;
        bool valid=s->exclusive_valid && s->exclusive_address==a && s->exclusive_size==bytes && s->exclusive_generation==e->write_generation;
        s->exclusive_valid=false; bool success=false;
        if (valid) {
            if (!e->borrowed && mprotect(e->guest,e->map_size,PROT_READ|PROT_WRITE)) return BB_INTERNAL;
            uint8_t *base=e->borrowed?e->guest_write:e->guest;
            int order=(w&0x8000)?__ATOMIC_RELEASE:__ATOMIC_RELAXED;
            if (bytes==8) {
                uint64_t expected=s->exclusive_value, replacement=readreg(s,rd,false);
                success=__atomic_compare_exchange_n((uint64_t *)(void *)(base+off),&expected,replacement,false,order,__ATOMIC_RELAXED);
            } else {
                uint32_t expected=(uint32_t)s->exclusive_value, replacement=(uint32_t)readreg(s,rd,false);
                success=__atomic_compare_exchange_n((uint32_t *)(void *)(base+off),&expected,replacement,false,order,__ATOMIC_RELAXED);
            }
            if (!e->borrowed && mprotect(e->guest,e->map_size,PROT_READ)) { e->poisoned=true; return BB_INTERNAL; }
            if (success) { invalidate(e); ++e->write_generation; }
        }
        writereg(s,status,false,false,success?0:1);
    } else if ((w&0x3ffffc00)==0x089ffc00) {
        /* STLRB/STLRH/STLR W/STLR X. */
        size_t off, bytes=(size_t)1<<((w>>30)&3); a=readreg(s,rn,true);
        if (a&(bytes-1)) return BB_ALIGNMENT;
        if (!range(e,a,bytes,BB_W,&off) || (e->perms[off/GPAGE]&BB_X)) return BB_MEMORY;
        if (!e->borrowed && mprotect(e->guest,e->map_size,PROT_READ|PROT_WRITE)) return BB_INTERNAL;
        uint8_t *base=e->borrowed?e->guest_write:e->guest;
        v=readreg(s,rd,false);
        if (bytes==1) __atomic_store_n(base+off,(uint8_t)v,__ATOMIC_RELEASE);
        else if (bytes==2) __atomic_store_n((uint16_t *)(void *)(base+off),(uint16_t)v,__ATOMIC_RELEASE);
        else if (bytes==4) __atomic_store_n((uint32_t *)(void *)(base+off),(uint32_t)v,__ATOMIC_RELEASE);
        else __atomic_store_n((uint64_t *)(void *)(base+off),v,__ATOMIC_RELEASE);
        if (!e->borrowed && mprotect(e->guest,e->map_size,PROT_READ)) { e->poisoned=true; return BB_INTERNAL; }
        invalidate(e); ++e->write_generation;
    } else if ((w&0x3ffffc00)==0x08dffc00) {
        /* LDARB/LDARH/LDAR W/LDAR X. */
        size_t off, bytes=(size_t)1<<((w>>30)&3); a=readreg(s,rn,true);
        if (a&(bytes-1)) return BB_ALIGNMENT;
        if (!range(e,a,bytes,BB_R,&off)) return BB_MEMORY;
        const uint8_t *p=e->guest+off;
        if (bytes==1) v=__atomic_load_n(p,__ATOMIC_ACQUIRE);
        else if (bytes==2) v=__atomic_load_n((const uint16_t *)(const void *)p,__ATOMIC_ACQUIRE);
        else if (bytes==4) v=__atomic_load_n((const uint32_t *)(const void *)p,__ATOMIC_ACQUIRE);
        else v=__atomic_load_n((const uint64_t *)(const void *)p,__ATOMIC_ACQUIRE);
        writereg(s,rd,false,bytes==8,v);
    } else if ((w&0x3f000000)==0x1c000000 && (w>>30)!=3) {
        /* LDR St/Dt/Qt, literal: PC-relative, the rest of the vector cleared. */
        size_t bytes=(size_t)4<<(w>>30); uint64_t lanes[2]={0,0};
        a=s->pc+(uint64_t)(sext((w>>5)&0x7ffff,19)*4);
        if (!read_u(e,a,lanes,bytes)) return BB_MEMORY;
        memcpy(s->v[rd],lanes,16);
    } else if ((w&0xbf9f0000)==0x0d000000 || (w&0xbf800000)==0x0d800000) {
        /* AdvSIMD LD1-LD4/ST1-ST4 single structure (one lane of 1-4 consecutive
         * registers) and LD1R-LD4R, with optional post-index. */
        bool post=(w>>23)&1, load=(w>>22)&1, rep=false; unsigned opcode=(w>>13)&7, sbit=(w>>12)&1, size=(w>>10)&3, q=(w>>30)&1, rm=(w>>16)&31;
        unsigned selem=((((opcode&1)<<1)|((w>>21)&1)))+1, scale=0, index=0;
        switch (opcode>>1) {
        case 0: scale=0; index=(q<<3)|(sbit<<2)|size; break;
        case 1: if (size&1) return BB_UNSUPPORTED; scale=1; index=(q<<2)|(sbit<<1)|(size>>1); break;
        case 2: if (size&2) return BB_UNSUPPORTED;
                if (!size) { scale=2; index=(q<<1)|sbit; } else { if (sbit) return BB_UNSUPPORTED; scale=3; index=q; } break;
        case 3: if (!load || sbit) return BB_UNSUPPORTED; scale=size; rep=true; break;
        }
        size_t bytes=(size_t)1<<scale; uint64_t base=readreg(s,rn,true);
        for (unsigned r=0;r<selem;r++) {
            uint8_t lanes[16]; unsigned reg=(rd+r)&31; a=base+r*bytes;
            memcpy(lanes,s->v[reg],16);
            if (rep) {
                uint8_t elem[8]; if (!read_u(e,a,elem,bytes)) return BB_MEMORY;
                for (size_t i=0;i<16;i+=bytes) memcpy(lanes+i,elem,bytes);
                if (!q) memset(lanes+8,0,8);
            } else if (load) { if (!read_u(e,a,lanes+index*bytes,bytes)) return BB_MEMORY; }
            else if (!write_u(e,a,lanes+index*bytes,bytes)) return BB_MEMORY;
            if (load) memcpy(s->v[reg],lanes,16);
        }
        if (post) writereg(s,rn,true,true,base+(rm==31?(uint64_t)bytes*selem:readreg(s,rm,false)));
    } else if ((w&0xbfbf0000)==0x0c000000 || (w&0xbfa00000)==0x0c800000) {
        /* AdvSIMD LD1/ST1 multiple structures, 1-4 consecutive registers. */
        bool post=(w>>23)&1, load=(w>>22)&1; unsigned opcode=(w>>12)&15, q=(w>>30)&1, rm=(w>>16)&31, nregs, inter=1;
        switch (opcode) { case 7: nregs=1; break; case 10: nregs=2; break; case 6: nregs=3; break; case 2: nregs=4; break;
                          case 8: nregs=inter=2; break; case 4: nregs=inter=3; break; case 0: nregs=inter=4; break;   /* LD2-LD4/ST2-ST4: interleaved */
                          default: return BB_UNSUPPORTED; }
        size_t each=q?16:8, total=each*nregs; uint8_t buf[64]; uint64_t base=readreg(s,rn,true);
        if (inter>1) {
            size_t esize=(size_t)1<<((w>>10)&3), nel=each/esize; uint8_t regs[4][16];
            if (esize==8 && !q) return BB_UNSUPPORTED;   /* reserved */
            for (unsigned r=0;r<nregs;r++) memcpy(regs[r],s->v[(rd+r)&31],16);
            if (load) {
                if (!read_u(e,base,buf,total)) return BB_MEMORY;
                for (size_t i=0;i<nel;i++) for (unsigned r=0;r<nregs;r++) memcpy(regs[r]+i*esize,buf+(i*nregs+r)*esize,esize);
                for (unsigned r=0;r<nregs;r++) { if (!q) memset(regs[r]+8,0,8); memcpy(s->v[(rd+r)&31],regs[r],16); }
            } else {
                for (size_t i=0;i<nel;i++) for (unsigned r=0;r<nregs;r++) memcpy(buf+(i*nregs+r)*esize,regs[r]+i*esize,esize);
                if (!write_u(e,base,buf,total)) return BB_MEMORY;
            }
        } else if (load) {
            if (!read_u(e,base,buf,total)) return BB_MEMORY;
            for (unsigned i=0;i<nregs;i++) { uint64_t lanes[2]={0,0}; memcpy(lanes,buf+i*each,each); memcpy(s->v[(rd+i)&31],lanes,16); }
        } else {
            for (unsigned i=0;i<nregs;i++) memcpy(buf+i*each,s->v[(rd+i)&31],each);
            if (!write_u(e,base,buf,total)) return BB_MEMORY;
        }
        if (post) writereg(s,rn,true,true,base+(rm==31?(uint64_t)total:readreg(s,rm,false)));
    } else if (((w&0x3f000000)==0x39000000 || (w&0x3f200000)==0x38000000 || (w&0x3f200c00)==0x38200800) && ((w>>22)&3)>=2) {
        /* Sign-extending loads LDRSB/LDRSH/LDRSW to W (opc 3) or X (opc 2), all
         * addressing forms: unsigned offset, unscaled, pre/post-index, register
         * offset. PRFM (size 3, opc 2) is a hint: no architectural access. */
        unsigned size=(w>>30)&3, opc=(w>>22)&3; bool uimm=(w&0x3f000000)==0x39000000, reg=!uimm && (w&0x00200c00)==0x00200800;
        unsigned idx=uimm||reg?0:(w>>10)&3;   /* unscaled 0, post 1, pre 3; 2 is unprivileged */
        if (size==3 && opc==2 && (uimm || reg || idx==0)) { s->pc=next; return BB_STOP; }
        if (size==3 || (size==2 && opc==3) || idx==2) return BB_UNSUPPORTED;
        size_t bytes=(size_t)1<<size; uint64_t base=readreg(s,rn,true), updated=base;
        if (uimm) a=base+(uint64_t)((w>>10)&0xfff)*bytes;
        else if (reg) {
            unsigned option=(w>>13)&7, rm=(w>>16)&31;
            if (option!=2 && option!=3 && option!=6 && option!=7) return BB_UNSUPPORTED;
            uint64_t offset=readreg(s,rm,false);
            if (option==2) offset=(uint32_t)offset; else if (option==6) offset=(uint64_t)sext((uint32_t)offset,32);
            if ((w>>12)&1) offset<<=size;
            a=base+offset;
        } else {
            updated=base+(uint64_t)sext((w>>12)&0x1ff,9);
            if (idx && rn!=31 && rn==rd) return BB_UNSUPPORTED;
            a=idx==1?base:updated;
        }
        v=0; if (!read_u(e,a,&v,bytes)) return BB_MEMORY;
        writereg(s,rd,false,opc==2,(uint64_t)sext(v,(unsigned)bytes*8));
        if (!uimm && !reg && idx) writereg(s,rn,true,true,updated);
    } else if ((w&0x3f200c00)==0x38200800 && ((w>>22)&3)<2) {
        /* Integer register-offset loads/stores: UXTW, LSL, SXTW, SXTX. */
        unsigned size=(w>>30)&3, option=(w>>13)&7, rm=(w>>16)&31;
        if (option!=2 && option!=3 && option!=6 && option!=7) return BB_UNSUPPORTED;
        uint64_t offset=readreg(s,rm,false);
        if (option==2) offset=(uint32_t)offset;
        else if (option==6) offset=(uint64_t)sext((uint32_t)offset,32);
        if ((w>>12)&1) offset<<=size;
        a=readreg(s,rn,true)+offset;
        size_t bytes=(size_t)1<<size;
        if ((w>>22)&1) {
            v=0; if (!read_u(e,a,&v,bytes)) return BB_MEMORY;
            writereg(s,rd,false,size==3,v);
        } else {
            v=readreg(s,rd,false); if (!write_u(e,a,&v,bytes)) return BB_MEMORY;
        }
    } else if ((w&0xffc00000)==0xb9800000) {
        /* LDRSW Xt, [Xn|SP, #pimm12 * 4]. */
        uint32_t word; a=readreg(s,rn,true)+(uint64_t)((w>>10)&0xfff)*4;
        if (!read_u(e,a,&word,sizeof(word))) return BB_MEMORY;
        int64_t signed_value=(int64_t)word;
        if (word&0x80000000u) signed_value-=INT64_C(0x100000000);
        writereg(s,rd,false,true,(uint64_t)signed_value);
    } else if ((w&0xbfc00000)==0x39400000 || (w&0xbfc00000)==0x39000000) {
        bool load=(w>>22)&1; size_t bytes=(w&0x40000000)?2:1;
        a=readreg(s,rn,true)+(uint64_t)((w>>10)&0xfff)*bytes;
        if (load) {
            v=0; if (!read_u(e,a,&v,bytes)) return BB_MEMORY;
            writereg(s,rd,false,false,v);
        } else {
            v=readreg(s,rd,false);
            if (!write_u(e,a,&v,bytes)) return BB_MEMORY;
        }
    } else if ((w&0xffc00000)==0xb9400000 || (w&0xffc00000)==0xf9400000 || (w&0xffc00000)==0xb9000000 || (w&0xffc00000)==0xf9000000) {
        unsigned n=(w&0x40000000)?8:4; bool load=(w>>22)&1; a=readreg(s,rn,true)+(uint64_t)((w>>10)&0xfff)*n;
        if(load) { v=0; if(!read_u(e,a,&v,n)) return BB_MEMORY; writereg(s,rd,false,n==8,v); }
        else { v=readreg(s,rd,false); if(!write_u(e,a,&v,n)) return BB_MEMORY; }
    } else if ((w&0x3f200c00)==0x38000000 && ((w>>22)&3)<2) {
        /* Unscaled integer LDUR/STUR B/H/W/X, signed byte offset. */
        size_t bytes=(size_t)1<<((w>>30)&3);
        a=readreg(s,rn,true)+(uint64_t)sext((w>>12)&0x1ff,9);
        if ((w>>22)&1) {
            v=0; if (!read_u(e,a,&v,bytes)) return BB_MEMORY;
            writereg(s,rd,false,bytes==8,v);
        } else {
            v=readreg(s,rd,false); if (!write_u(e,a,&v,bytes)) return BB_MEMORY;
        }
    } else if ((w&0x3f200400)==0x38000400 && ((w>>22)&3)<2) {
        /* Integer pre/post-index B/H/W/X with signed byte writeback. */
        if (rn!=31 && rn==rd) return BB_UNSUPPORTED;
        size_t bytes=(size_t)1<<((w>>30)&3); bool load=(w>>22)&1;
        uint64_t old=readreg(s,rn,true), updated=old+(uint64_t)sext((w>>12)&0x1ff,9);
        a=(w&0x800)?updated:old;
        if (load) { v=0; if (!read_u(e,a,&v,bytes)) return BB_MEMORY; writereg(s,rd,false,bytes==8,v); }
        else { v=readreg(s,rd,false); if (!write_u(e,a,&v,bytes)) return BB_MEMORY; }
        writereg(s,rn,true,true,updated);
    } else if ((w&0x3f200c00)==0x3c000000) {
        /* Unscaled SIMD/FP B/H/S/D/Q load and store. */
        unsigned size=(w>>30)&3, opc=(w>>22)&3;
        if (opc>=2 && size!=0) return BB_UNSUPPORTED;
        size_t bytes=opc>=2?16:(size_t)1<<size;
        a=readreg(s,rn,true)+(uint64_t)sext((w>>12)&0x1ff,9);
        if (opc&1) {
            uint64_t lanes[2]={0,0}; if (!read_u(e,a,lanes,bytes)) return BB_MEMORY;
            memcpy(s->v[rd],lanes,16);
        } else if (!write_u(e,a,s->v[rd],bytes)) return BB_MEMORY;
    } else if ((w&0x3f200400)==0x3c000400) {
        /* SIMD/FP B/H/S/D/Q pre- and post-indexed loads/stores. */
        unsigned size=(w>>30)&3, opc=(w>>22)&3;
        if (opc>=2 && size!=0) return BB_UNSUPPORTED;
        size_t bytes=opc>=2?16:(size_t)1<<size;
        uint64_t old=readreg(s,rn,true), updated=old+(uint64_t)sext((w>>12)&0x1ff,9);
        a=(w&0x800)?updated:old;
        if (opc&1) {
            uint64_t lanes[2]={0,0}; if (!read_u(e,a,lanes,bytes)) return BB_MEMORY;
            memcpy(s->v[rd],lanes,16);
        } else if (!write_u(e,a,s->v[rd],bytes)) return BB_MEMORY;
        writereg(s,rn,true,true,updated);
    } else if ((w&0x3f000000)==0x3d000000) {
        /* SIMD/FP unsigned immediate B/H/S/D/Q loads and stores. */
        unsigned size=(w>>30)&3, opc=(w>>22)&3;
        if (opc>=2 && size!=0) return BB_UNSUPPORTED;
        size_t bytes=opc>=2 ? 16 : (size_t)1<<size;
        a=readreg(s,rn,true)+(uint64_t)((w>>10)&0xfff)*bytes;
        if (opc&1) {
            uint64_t lanes[2]={0,0};
            if (!read_u(e,a,lanes,bytes)) return BB_MEMORY;
            memcpy(s->v[rd],lanes,sizeof(lanes));
        } else if (!write_u(e,a,s->v[rd],bytes)) return BB_MEMORY;
    } else if ((w&0x3e000000)==0x2c000000) {
        /* SIMD S/D/Q pair: signed offset, pre-index, post-index. */
        unsigned size=(w>>30)&3, mode=(w>>23)&3, rt2=(w>>10)&31;
        bool load=(w>>22)&1; if (size==3 || !mode || (load && rd==rt2)) return BB_UNSUPPORTED;
        size_t bytes=(size_t)4<<size; uint8_t pair[32];
        uint64_t old=readreg(s,rn,true); int64_t d=sext((w>>15)&0x7f,7)*(int64_t)bytes;
        a=mode==1?old:old+(uint64_t)d;
        if (load) {
            if (!read_u(e,a,pair,bytes*2)) return BB_MEMORY;
            uint64_t first[2]={0,0},second[2]={0,0};
            memcpy(first,pair,bytes); memcpy(second,pair+bytes,bytes);
            memcpy(s->v[rd],first,16); memcpy(s->v[rt2],second,16);
        } else {
            memcpy(pair,s->v[rd],bytes); memcpy(pair+bytes,s->v[rt2],bytes);
            if (!write_u(e,a,pair,bytes*2)) return BB_MEMORY;
        }
        if (mode!=2) writereg(s,rn,true,true,old+(uint64_t)d);
    } else if ((w&0x7e000000)==0x28000000) {
        /* Integer W/X pairs: signed offset, pre-index and post-index. */
        bool load=(w&0x00400000)!=0; unsigned rt2=(w>>10)&31, mode=(w>>23)&3;
        size_t bytes=sf?8:4; int64_t d=sext((w>>15)&0x7f,7)*(int64_t)bytes;
        if (!mode || (load && rd==rt2) || (mode!=2 && rn!=31 && (rn==rd || rn==rt2))) return BB_UNSUPPORTED;
        uint64_t old=readreg(s,rn,true), first=0, second=0;
        a=mode==1?old:old+(uint64_t)d;
        uint8_t pair[16];
        if (load) {
            if (!read_u(e,a,pair,bytes*2)) return BB_MEMORY;
            memcpy(&first,pair,bytes); memcpy(&second,pair+bytes,bytes);
            writereg(s,rd,false,sf,first); writereg(s,rt2,false,sf,second);
        } else {
            first=readreg(s,rd,false); second=readreg(s,rt2,false);
            memcpy(pair,&first,bytes); memcpy(pair+bytes,&second,bytes);
            if (!write_u(e,a,pair,bytes*2)) return BB_MEMORY;
        }
        if (mode!=2) writereg(s,rn,true,true,old+(uint64_t)d);
    } else if ((w&0xfffffc00)==0x4e080c00) {
        /* DUP Vd.2D, Xn. */
        s->v[rd][0]=s->v[rd][1]=readreg(s,rn,false);
    } else if ((w&0xfffffc00)==0x9e670000 || (w&0xfffffc00)==0x1e270000) {
        /* FMOV Dd,Xn / Sd,Wn clears bits above the scalar. */
        v=readreg(s,rn,false); s->v[rd][0]=(w>>31)?v:(uint32_t)v; s->v[rd][1]=0;
    } else if ((w&0xffe01fe0)==0x1e201000) {
        /* FMOV Sd, #imm: expand ARM's eight-bit floating-point immediate. */
        unsigned imm=(w>>13)&255;
        s->v[rd][0]=((uint32_t)(imm&0x80)<<24) | ((uint32_t)((~imm>>6)&1)<<30) |
                     ((imm&0x40)?0x3e000000u:0) | ((imm&0x3f)<<19);
        s->v[rd][1]=0;
    } else if ((w&0xbfe0fc00)==0x0ea01c00) {
        /* Vector ORR, including MOV Vd.16B,Vn.16B. */
        unsigned rm=(w>>16)&31; uint64_t lo=s->v[rn][0]|s->v[rm][0], hi=s->v[rn][1]|s->v[rm][1];
        s->v[rd][0]=lo; s->v[rd][1]=(w&(1u<<30))?hi:0;
    } else if ((w&0xfffffc00)==0x4e081c00 || (w&0xfffffc00)==0x4e181c00) {
        /* INS Vd.D[lane], Xn preserves the other lane. */
        s->v[rd][(w>>20)&1]=readreg(s,rn,false);
    } else if ((w&0xffffffe0)==0x6f00e400 || (w&0xffffffe0)==0x2f00e400) {
        /* MOVI Vd.2D or Dd, #0. */
        s->v[rd][0]=s->v[rd][1]=0;
    } else if ((w&0xffffffe0)==0xd53bd040) { writereg(s,rd,false,true,s->tpidr_el0); }
    else if (w!=0xd503201f) return BB_UNSUPPORTED;
    s->pc=next; return BB_STOP;
}
/* LDR/STR x9 against the context in x0, keeping all guest registers in memory. */
static uint32_t ldr(unsigned off) { return 0xf9400009u | ((off/8)<<10); }
static uint32_t str(unsigned off) { return 0xf9000009u | ((off/8)<<10); }
static unsigned regoff(unsigned r) { return r==31 ? (unsigned)offsetof(bb_state,sp) : r*8; }
static size_t emit_imm(uint32_t *out, uint64_t v) {
    size_t n=0; out[n++]=0xd2800009u | ((uint32_t)(v&0xffff)<<5);
    for (unsigned shift=1;shift<4;++shift)
        out[n++]=0xf2800009u | (shift<<21) | ((uint32_t)((v>>(shift*16))&0xffff)<<5);
    return n;
}
static size_t lower(uint32_t w, uint64_t pc, uint32_t *out) {
    unsigned rd=w&31, rn=(w>>5)&31; size_t n=0;
    if(w==0xd503201f) return 0;
    if ((w & 0x1f000000) == 0x10000000) {
        if (rd==31) return 0;
        int64_t d=sext((((w>>5)&0x7ffff)*4ULL)+((w>>29)&3),21);
        uint64_t address=(w&0x80000000)?(pc&~UINT64_C(4095))+(uint64_t)(d*4096):pc+(uint64_t)d;
        /* Materialize the guest address, never the cache PC. MOVZ/MOVK leave NZCV alone. */
        n+=emit_imm(out+n,address);
        out[n++]=str(regoff(rd));
    } else if(wide(w)) {
        if(rd==31) return 0;
        if((w&0x7f800000)==0x72800000) out[n++]=ldr(regoff(rd));
        out[n++]=(w&~31u)|9; out[n++]=str(regoff(rd));
    } else {
        out[n++]=ldr(regoff(rn)); out[n++]=(w&~0x3ffu)|(9u<<5)|9u; out[n++]=str(regoff(rd));
    }
    return n;
}
static size_t lower_control(uint32_t w, uint64_t pc, uint32_t *out) {
    size_t n=0; bool direct=(w&0x7c000000)==0x14000000;
    bool link=direct ? (w>>31)!=0 : (w&0xfffffc1f)==0xd63f0000;
    if (direct) n+=emit_imm(out+n,pc+(uint64_t)(sext(w&0x3ffffff,26)*4));
    else out[n++]=ldr(regoff((w>>5)&31));
    /* Save the target before updating LR, including BLR x30. */
    out[n++]=str((unsigned)offsetof(bb_state,pc));
    if (link) { n+=emit_imm(out+n,pc+4); out[n++]=str(regoff(30)); }
    return n;
}
/* ------------------------------------------------------------------------
 * Register-only FP and AdvSIMD data processing, executed natively.
 *
 * Every instruction accepted here belongs to an A64 encoding class whose
 * allocated members read and write only the named SIMD/FP or general
 * registers, and possibly NZCV: no memory access, no control transfer, no
 * system register other than NZCV (FPCR is the host's default, round to
 * nearest; FPSR's cumulative flags are not guest-visible -- MRS/MSR of either
 * stays unsupported). The guest instruction runs unchanged except its register
 * fields, which are renamed to host scratch registers loaded from and stored
 * back to bb_state: v0 = Vd, v1 = Vn, v2 = Vm, v3 = Va, v4..v7 = a TBL/TBX
 * table, x9 = a general operand (register 31 is XZR here, never SP). The
 * scratch registers are caller-saved in the host ABI the block is called with.
 * Vd is always loaded first, so lane-preserving forms (INS, BSL, FMLA, SRI, the
 * D[1] FMOV) see the guest's prior value. FP16 forms are not accepted.
 * ------------------------------------------------------------------------ */
enum { SV_D=1, SV_N=2, SV_M=4, SV_A=8, SG_D=16, SG_N=32, S_FLAGS_IN=64, S_FLAGS_OUT=128, SV_TABLE=256, SV_MH=512 };
static unsigned simd_roles(uint32_t w) {
    unsigned ptype=(w>>22)&3;
    bool fp_ok=ptype<2;
    if ((w&0x5f20fc00)==0x1e200000) {             /* FP <-> integer conversion */
        unsigned op=(w>>16)&7, rmode=(w>>19)&3, sf=w>>31;
        if (w&0x20000000) return 0;
        if (op==6 || op==7) {                      /* FMOV general <-> FP */
            bool lowhalf=rmode==0 && ((sf==0 && ptype==0) || (sf==1 && ptype==1));
            bool upper=rmode==1 && sf==1 && ptype==2;
            if (!lowhalf && !upper) return 0;
            return op==6 ? SG_D|SV_N : SV_D|SG_N;
        }
        if (!fp_ok) return 0;
        if (op<=1) return SG_D|SV_N;               /* FCVT{N,P,M,Z}{S,U} */
        if (rmode) return 0;
        if (op==2 || op==3) return SV_D|SG_N;      /* SCVTF, UCVTF */
        return SG_D|SV_N;                          /* FCVTA{S,U} */
    }
    if ((w&0xff207c00)==0x1e204000) {             /* FP 1-source */
        unsigned op=(w>>15)&63;
        if (!fp_ok) return 0;
        if (op<=3 || (op>=8 && op<=15 && op!=13)) return SV_D|SV_N;
        if ((op==4 && ptype==1) || (op==5 && ptype==0) || op==7) return SV_D|SV_N;   /* FCVT to S, D, H */
        return 0;
    }
    if ((w&0xff20fc07)==0x1e202000) return fp_ok ? SV_N|SV_M|S_FLAGS_OUT : 0;          /* FCMP{E} */
    if ((w&0xff201fe0)==0x1e201000) return fp_ok ? SV_D : 0;                            /* FMOV #imm */
    if ((w&0xff200c00)==0x1e200400) return fp_ok ? SV_N|SV_M|S_FLAGS_IN|S_FLAGS_OUT : 0; /* FCCMP{E} */
    if ((w&0xff200c00)==0x1e200800) return fp_ok && ((w>>12)&15)<=8 ? SV_D|SV_N|SV_M : 0; /* FP 2-source */
    if ((w&0xff200c00)==0x1e200c00) return fp_ok ? SV_D|SV_N|SV_M|S_FLAGS_IN : 0;       /* FCSEL */
    if ((w&0xff000000)==0x1f000000) return fp_ok ? SV_D|SV_N|SV_M|SV_A : 0;             /* FP 3-source */
    if ((w&0x9f000000)==0x0e000000 || (w&0xdf000000)==0x5e000000) {   /* AdvSIMD vector / scalar */
        bool scalar=(w>>30)&1 && (w&0x10000000);
        if ((w&0x9fe08400)==0x0e000400 || (w&0xdfe08400)==0x5e000400) {             /* copy */
            unsigned imm5=(w>>16)&31, imm4=(w>>11)&15; bool op=(w>>29)&1, q=(w>>30)&1;
            if (!(imm5&15)) return 0;
            if (scalar) return !op && imm4==0 ? SV_D|SV_N : 0;                       /* DUP (element), scalar */
            if (op) return q ? SV_D|SV_N : 0;                                        /* INS (element) */
            if (imm4==0) return SV_D|SV_N;                                           /* DUP (element) */
            if (imm4==1) return SV_D|SG_N;                                           /* DUP (general) */
            if (imm4==3) return q ? SV_D|SG_N : 0;                                   /* INS (general) */
            if (imm4==5 || imm4==7) return SG_D|SV_N;                                /* SMOV, UMOV */
            return 0;
        }
        if ((w&0x9f200400)==0x0e200400 || (w&0xdf200400)==0x5e200400) return SV_D|SV_N|SV_M;   /* three same */
        if ((w&0x9f200c00)==0x0e200000 || (w&0xdf200c00)==0x5e200000) return SV_D|SV_N|SV_M;   /* three different */
        if ((w&0x9f3e0c00)==0x0e200800 || (w&0xdf3e0c00)==0x5e200800) return SV_D|SV_N;        /* two-register misc */
        if ((w&0x9f3e0c00)==0x0e300800 || (w&0xdf3e0c00)==0x5e300800) return SV_D|SV_N;        /* across lanes, pairwise */
        if (!scalar && (w&0xbf208c00)==0x0e000800) return SV_D|SV_N|SV_M;                      /* ZIP/UZP/TRN */
        if (!scalar && (w&0xbfe08400)==0x2e000000) return SV_D|SV_N|SV_M;                      /* EXT */
        if (!scalar && (w&0xbfe09c00)==0x0e000000) return SV_D|SV_TABLE|SV_M;                  /* TBL/TBX */
        return 0;
    }
    if ((w&0x9ff80400)==0x0f000400) return SV_D;                                               /* modified immediate */
    if (((w&0x9f800400)==0x0f000400 || (w&0xdf800400)==0x5f000400) && ((w>>19)&15)) return SV_D|SV_N; /* shift by immediate */
    if ((w&0x9f000400)==0x0f000000 || (w&0xdf000400)==0x5f000000)                              /* by element */
        return SV_D|SV_N|SV_M|(((w>>22)&3)==1?SV_MH:0);
    return 0;
}
/* Integer data processing the interpreter does not implement, all register-
 * only with register 31 as XZR (never SP): SBFM/BFM, CCMP/CCMN, ADC/SBC(S),
 * the 2-source shifts and divides, the 1-source bit and byte reversals and
 * counts, SMULH/UMULH. Guest Rd/Rn/Rm are renamed to x9/x10/x11. */
enum { SI_D=1024, SI_N=2048, SI_M=4096, SI_DIN=8192 };
static unsigned int_roles(uint32_t w) {
    bool sf=w>>31;
    if ((w&0x7f800000)==0x13000000) return SI_D|SI_N;                         /* SBFM */
    if ((w&0x7f800000)==0x33000000) return SI_D|SI_DIN|SI_N;                  /* BFM reads Rd */
    if ((w&0x3fe00c10)==0x3a400000) return SI_N|SI_M|S_FLAGS_IN|S_FLAGS_OUT;   /* CCMN/CCMP register */
    if ((w&0x3fe00c10)==0x3a400800) return SI_N|S_FLAGS_IN|S_FLAGS_OUT;        /* CCMN/CCMP immediate */
    if ((w&0x1fe0fc00)==0x1a000000) return SI_D|SI_N|SI_M|S_FLAGS_IN|((w>>29)&1?S_FLAGS_OUT:0);   /* ADC/SBC(S) */
    if ((w&0x7fe00000)==0x1ac00000) { unsigned op=(w>>10)&63;                /* 2-source */
        return op==2||op==3||(op>=8&&op<=11) ? SI_D|SI_N|SI_M : 0; }
    if ((w&0x7fff0000)==0x5ac00000) { unsigned op=(w>>10)&63;                /* 1-source */
        return op<=5 && (op!=3 || sf) ? SI_D|SI_N : 0; }
    if ((w&0xffe08000)==0x9b400000 || (w&0xffe08000)==0x9bc00000) return ((w>>10)&31)==31 ? SI_D|SI_N|SI_M : 0;   /* SMULH/UMULH */
    return 0;
}
static bool simd(uint32_t w) { return simd_roles(w)!=0 || int_roles(w)!=0; }
static uint32_t ldx(unsigned reg, unsigned t) { return reg==31 ? 0xd2800000u|t : 0xf9400000u|(reg<<10)|t; }   /* XZR as MOVZ #0 */
static uint32_t stx(unsigned reg, unsigned t) { return 0xf9000000u|(reg<<10)|t; }
static size_t lower_int(uint32_t w, uint32_t *out) {
    unsigned roles=int_roles(w), rd=w&31, rn=(w>>5)&31, rm=(w>>16)&31; size_t n=0; uint32_t op=w;
    if (roles&S_FLAGS_IN) { out[n++]=ldr((unsigned)offsetof(bb_state,nzcv)); out[n++]=0xd51b4209u; }
    if (roles&SI_DIN) out[n++]=ldx(rd,9);
    if (roles&SI_N) { out[n++]=ldx(rn,10); op=(op&~(31u<<5))|(10u<<5); }
    if (roles&SI_M) { out[n++]=ldx(rm,11); op=(op&~(31u<<16))|(11u<<16); }
    if (roles&SI_D) op=(op&~31u)|9;
    out[n++]=op;
    if ((roles&SI_D) && rd!=31) out[n++]=stx(rd,9);
    if (roles&S_FLAGS_OUT) { out[n++]=0xd53b4209u; out[n++]=str((unsigned)offsetof(bb_state,nzcv)); }
    return n;
}
/* LDR/STR Qq, [x10, #reg*16]: x10 is &state->v[0]. */
static uint32_t ldq(unsigned reg, unsigned q) { return 0x3dc00000u|(reg<<10)|(10u<<5)|q; }
static uint32_t stq(unsigned reg, unsigned q) { return 0x3d800000u|((reg)<<10)|(10u<<5)|q; }
static size_t lower_simd(uint32_t w, uint32_t *out) {
    unsigned roles=simd_roles(w), rd=w&31, rn=(w>>5)&31, rm=(w>>16)&31, ra=(w>>10)&31; size_t n=0;
    uint32_t op=w;
    out[n++]=0x9100000au|((unsigned)offsetof(bb_state,v)<<10);   /* add x10, x0, #v */
    if (roles&S_FLAGS_IN) { out[n++]=ldr((unsigned)offsetof(bb_state,nzcv)); out[n++]=0xd51b4209u; }   /* msr nzcv, x9 */
    if (roles&SV_D) { out[n++]=ldq(rd,0); op=(op&~31u)|0; }
    if (roles&SG_D) op=(op&~31u)|9;
    if (roles&SV_N) { out[n++]=ldq(rn,1); op=(op&~(31u<<5))|(1u<<5); }
    if (roles&SV_TABLE) { unsigned len=((w>>13)&3)+1;
        for (unsigned i=0;i<len;i++) out[n++]=ldq((rn+i)&31,4+i);
        op=(op&~(31u<<5))|(4u<<5); }
    if (roles&SG_N) { out[n++]= rn==31 ? 0xd2800009u : ldr(regoff(rn)); op=(op&~(31u<<5))|(9u<<5); }
    if (roles&SV_M) {
        if (roles&SV_MH) { out[n++]=ldq(rm&15,2); op=(op&~(15u<<16))|(2u<<16); }   /* M (bit 20) is an index bit */
        else { out[n++]=ldq(rm,2); op=(op&~(31u<<16))|(2u<<16); }
    }
    if (roles&SV_A) { out[n++]=ldq(ra,3); op=(op&~(31u<<10))|(3u<<10); }
    out[n++]=op;
    if (roles&SV_D) out[n++]=stq(rd,0);
    if ((roles&SG_D) && rd!=31) out[n++]=str(regoff(rd));
    if (roles&S_FLAGS_OUT) { out[n++]=0xd53b4209u; out[n++]=str((unsigned)offsetof(bb_state,nzcv)); }   /* mrs x9, nzcv */
    return n;
}
static bb_result fetch(bb_engine *e, uint64_t pc, uint32_t *word) {
    size_t off; if(pc&3) return BB_ALIGNMENT;
    if(!range(e,pc,4,BB_X,&off)) return BB_MEMORY;
    memcpy(word,e->guest+off,4); return BB_STOP;
}
static struct block *lookup(bb_engine *e, uint64_t pc) {
    for(size_t i=0;i<e->slots;++i) if(e->blocks[i].valid && e->blocks[i].pc==pc) return &e->blocks[i];
    return NULL;
}
static bb_result translate(bb_engine *e, uint64_t pc, struct block **out) {
    uint32_t code[SLOT/4]; size_t n=0, count=0; uint32_t w; bb_result r=fetch(e,pc,&w); if(r!=BB_STOP) return r;
    bool control=native_control(w), has_simd=simd(w), native=fast(w) || has_simd || control;
    /* A native-only FP/SIMD instruction is a block of its own, so any budget
     * of at least one runs it natively (the interpreter cannot step it). */
    if(control) { n=lower_control(w,pc,code); count=1; }
    else if(has_simd) { n=int_roles(w)?lower_int(w,code):lower_simd(w,code); count=1; }
    else if(native) while(count<MAX_BLOCK) {
        r=fetch(e,pc+count*4,&w); if(r!=BB_STOP || !fast(w)) break;
        n+=lower(w,pc+count*4,code+n); ++count;
    }
    else count=1;
    size_t slot=e->next++ % e->slots; if(e->blocks[slot].valid) ++e->stats.evictions;
    struct block *b=&e->blocks[slot]; *b=(struct block){pc,(uint8_t)count,true,native,control,has_simd};
    if(native) { code[n++]=0xd65f03c0; memcpy(e->rw+slot*SLOT,code,n*4); sys_icache_invalidate(e->rx+slot*SLOT,n*4); }
    ++e->stats.translations; *out=b; return BB_STOP;
}
static bb_result run_mode(bb_engine *e, bb_state *s, uint64_t stop_pc, size_t budget, bool reference) {
    if(!e || !s || e->poisoned) return BB_INTERNAL;
    while(s->pc!=stop_pc) {
        if(!budget) return BB_BUDGET;
        size_t lo=0,hi=e->gate_count;
        while (lo<hi) { size_t m=lo+(hi-lo)/2; if (e->gates[m].address<s->pc) lo=m+1; else hi=m; }
        if (lo<e->gate_count && s->pc==e->gates[lo].address) {
            struct host_gate gate=e->gates[lo];
            uint64_t lr=s->x[30];
            ++e->write_generation; s->exclusive_valid=false;
            /* Release the engine lock across the host callback: the callback
             * may block in a guest synchronization primitive or re-enter the
             * guest on this thread, and another guest thread must be free to
             * run meanwhile. Gate metadata is immutable after setup, so the
             * copied `gate` stays valid without the lock. */
            engine_unlock(e);
            bool gate_ok = gate.gate(s,gate.opaque);
            engine_lock(e);
            if (!gate_ok) return BB_INTERNAL;
            if (s->pc!=gate.address) {
                /* A gate's non-local return (guest longjmp): resume at the
                 * restored guest PC, which must be aligned executable guest code. */
                size_t xoff; if ((s->pc&3) || !range(e,s->pc,4,BB_X,&xoff)) return BB_INTERNAL;
                ++e->write_generation; --budget; continue;
            }
            if (s->x[30]!=lr) return BB_INTERNAL;
            ++e->write_generation;
            s->pc=lr; --budget; continue;
        }
        struct block *b=lookup(e,s->pc); bb_result r;
        if(!b && (r=translate(e,s->pc,&b))!=BB_STOP) return r;
        bool stop_inside = stop_pc > s->pc && stop_pc - s->pc < (uint64_t)b->count * 4;
        if(!reference && b->native && b->count<=budget && !stop_inside) {
            size_t slot=(size_t)(b-e->blocks); ((void (*)(bb_state *))(void *)(e->rx+slot*SLOT))(s);
            if(!b->control) s->pc+=(uint64_t)b->count*4;
            budget-=b->count; ++e->stats.native_blocks; e->stats.native_instructions+=b->count;
        } else {
            uint32_t w; if((r=fetch(e,s->pc,&w))!=BB_STOP) return r;
            if((r=step(e,s,w))!=BB_STOP) return r;
            --budget; ++e->stats.interpreted_instructions;
        }
    }
    return BB_STOP;
}
bb_result bb_run(bb_engine *e, bb_state *s, uint64_t stop_pc, size_t budget) {
    if (!e) return BB_INTERNAL;
    engine_lock(e); bb_result r=run_mode(e,s,stop_pc,budget,false); engine_unlock(e); return r;
}
#ifdef BB_TESTING
bb_result bb_run_reference(bb_engine *e, bb_state *s, uint64_t stop_pc, size_t budget) {
    if (!e) return BB_INTERNAL;
    engine_lock(e); bb_result r=run_mode(e,s,stop_pc,budget,true); engine_unlock(e); return r;
}
#endif
const char *bb_result_name(bb_result r) { switch(r) { case BB_STOP:return "stop"; case BB_BUDGET:return "budget"; case BB_UNSUPPORTED:return "unsupported"; case BB_MEMORY:return "memory"; case BB_ALIGNMENT:return "alignment"; case BB_INTERNAL:return "internal"; } return "unknown"; }
