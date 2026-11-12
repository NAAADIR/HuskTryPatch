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

#define GPAGE 4096u
#define SLOT 1024u
#define MAX_BLOCK 16u
#define MAX_SLOTS 64u
struct block { uint64_t pc; uint8_t count; bool valid, native; };
struct bb_engine {
    uint8_t *guest, *perms, *rw, *rx;
    uint8_t *guest_write;
    size_t size, map_size, npages, cache_size, slots, next;
    struct block blocks[MAX_SLOTS];
    bb_stats stats;
    bool poisoned;
    bool borrowed;
    uint64_t gate_address;
    bb_host_gate gate;
    void *gate_opaque;
};
static int64_t sext(uint64_t v, unsigned n) { return (int64_t)(v ^ (UINT64_C(1) << (n-1))) - (int64_t)(UINT64_C(1) << (n-1)); }
static bool range(bb_engine *e, uint64_t a, size_t n, unsigned perm, size_t *off) {
    uint64_t base = (uintptr_t)e->guest;
    if (e->poisoned || a < base || a - base > e->size || n > e->size - (size_t)(a - base)) return false;
    size_t p = (size_t)(a - base);
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
    e->guest=guest; e->guest_write=write; e->rw=rw; e->rx=rx; e->borrowed=true; return e;
}
bool bb_set_host_gate(bb_engine *e, uint64_t address, bb_host_gate gate, void *opaque) {
    if (!e || !address || !gate || range(e,address,1,0,NULL)) return false;
    e->gate_address=address; e->gate=gate; e->gate_opaque=opaque; return true;
}
void bb_destroy(bb_engine *e) { if (!e) return; if (!e->borrowed) { if (e->guest) munmap(e->guest, e->map_size); if (e->rw) munmap(e->rw, e->cache_size); if (e->rx) munmap(e->rx, e->cache_size); } free(e->perms); free(e); }
uint64_t bb_base(const bb_engine *e) { return (uintptr_t)e->guest; }
bool bb_protect(bb_engine *e, size_t off, size_t len, unsigned p) {
    if (!e || e->poisoned || (p & ~(BB_R | BB_W | BB_X)) || !len || off % GPAGE || len % GPAGE || off > e->npages * GPAGE || len > e->npages * GPAGE - off) return false;
    invalidate(e); for (size_t i = off / GPAGE; i < (off + len) / GPAGE; ++i) e->perms[i] = (uint8_t)p; return true;
}
bool bb_read(bb_engine *e, uint64_t a, void *out, size_t n) { size_t off; if (!e || (!out && n) || !range(e, a, n, BB_R, &off)) return false; if (n) memcpy(out, e->guest + off, n); return true; }
bool bb_write(bb_engine *e, uint64_t a, const void *src, size_t n) {
    size_t off; if (!e || (!src && n) || !range(e, a, n, BB_W, &off)) return false;
    if (!n) return true;
    if (e->borrowed) {
        /* Different virtual aliases may overlap physically; memmove cannot see it. */
        uintptr_t p=(uintptr_t)src, base=(uintptr_t)e->guest;
        if ((p>=base && p-base<e->size) || (p<base && n>base-p)) return false;
        invalidate(e);
        memmove(e->guest_write+off,src,n); return true;
    }
    /* All translated blocks are invalidated before any guest write. */
    invalidate(e);
    if (mprotect(e->guest, e->map_size, PROT_READ | PROT_WRITE)) return false;
    memmove(e->guest + off, src, n);
    if (mprotect(e->guest, e->map_size, PROT_READ)) { e->poisoned = true; return false; }
    return true;
}
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
static bb_result step(bb_engine *e, bb_state *s, uint32_t w) {
    uint64_t pc=s->pc, next=pc+4, v, a; unsigned rd=w&31, rn=(w>>5)&31; bool sf=(w>>31)&1;
    if (wide(w)) {
        unsigned sh=((w>>21)&3)*16; uint64_t mask=UINT64_C(0xffff)<<sh, imm=(uint64_t)((w>>5)&0xffff)<<sh;
        uint32_t op=w&0x7f800000;
        v = op==0x72800000 ? (readreg(s,rd,false)&~mask)|imm : op==0x12800000 ? ~imm : imm;
        writereg(s,rd,false,sf,v);
    } else if ((w&0x1f800000)==0x11000000) {
        bool sub=(w>>30)&1, set=(w>>29)&1; a=readreg(s,rn,true); v=(uint64_t)((w>>10)&0xfff)<<(((w>>22)&1)*12);
        uint64_t result=sub?a-v:a+v; if(set) s->nzcv=flags(a,v,result,sub,sf);
        writereg(s,rd,!set,sf,result);
    } else if ((w&0x9f000000)==0x10000000 || (w&0x9f000000)==0x90000000) {
        int64_t d=sext((((w>>5)&0x7ffff)*4ULL)+((w>>29)&3),21);
        v=(w&0x80000000)?(pc&~UINT64_C(4095))+(uint64_t)(d*4096):pc+(uint64_t)d; writereg(s,rd,false,true,v);
    } else if ((w&0xffe0ffe0)==0xaa0003e0) {
        writereg(s,rd,false,true,readreg(s,(w>>16)&31,false));
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
        if (!bb_read(e,a,&v,n)) return BB_MEMORY; writereg(s,rd,false,n==8,v);
    } else if ((w&0xffc00000)==0xb9400000 || (w&0xffc00000)==0xf9400000 || (w&0xffc00000)==0xb9000000 || (w&0xffc00000)==0xf9000000) {
        unsigned n=(w&0x40000000)?8:4; bool load=(w>>22)&1; a=readreg(s,rn,true)+(uint64_t)((w>>10)&0xfff)*n;
        if(load) { v=0; if(!bb_read(e,a,&v,n)) return BB_MEMORY; writereg(s,rd,false,n==8,v); }
        else { v=readreg(s,rd,false); if(!bb_write(e,a,&v,n)) return BB_MEMORY; }
    } else if ((w&0xffc00000)==0xa9800000 || (w&0xffc00000)==0xa8c00000) {
        /* 64-bit STP pre-index / LDP post-index, including common stack frames. */
        bool load=(w&0x00400000)!=0; unsigned rt2=(w>>10)&31; int64_t d=sext((w>>15)&0x7f,7)*8;
        /* Constrained-unpredictable writeback/register overlap is not emulated. */
        if ((rn != 31 && (rn == rd || rn == rt2)) || (load && rd == rt2)) return BB_UNSUPPORTED;
        uint64_t old=readreg(s,rn,true); a=load?old:old+(uint64_t)d; uint64_t pair[2];
        if(load) { if(!bb_read(e,a,pair,16)) return BB_MEMORY; }
        else { pair[0]=readreg(s,rd,false); pair[1]=readreg(s,rt2,false); if(!bb_write(e,a,pair,16)) return BB_MEMORY; }
        if(load) { writereg(s,rd,false,true,pair[0]); writereg(s,rt2,false,true,pair[1]); }
        writereg(s,rn,true,true,old+(uint64_t)d);
    } else if ((w&0xffffffe0)==0xd53bd040) { writereg(s,rd,false,true,s->tpidr_el0); }
    else if (w!=0xd503201f) return BB_UNSUPPORTED;
    s->pc=next; return BB_STOP;
}
/* LDR/STR x9 against the context in x0, keeping all guest registers in memory. */
static uint32_t ldr(unsigned off) { return 0xf9400009u | ((off/8)<<10); }
static uint32_t str(unsigned off) { return 0xf9000009u | ((off/8)<<10); }
static unsigned regoff(unsigned r) { return r==31 ? (unsigned)offsetof(bb_state,sp) : r*8; }
static size_t lower(uint32_t w, uint64_t pc, uint32_t *out) {
    unsigned rd=w&31, rn=(w>>5)&31; size_t n=0;
    if(w==0xd503201f) return 0;
    if ((w & 0x1f000000) == 0x10000000) {
        if (rd==31) return 0;
        int64_t d=sext((((w>>5)&0x7ffff)*4ULL)+((w>>29)&3),21);
        uint64_t address=(w&0x80000000)?(pc&~UINT64_C(4095))+(uint64_t)(d*4096):pc+(uint64_t)d;
        /* Materialize the guest address, never the cache PC. MOVZ/MOVK leave NZCV alone. */
        out[n++]=0xd2800009u | ((uint32_t)(address&0xffff)<<5);
        for (unsigned shift=1; shift<4; ++shift)
            out[n++]=0xf2800009u | (shift<<21) | ((uint32_t)((address>>(shift*16))&0xffff)<<5);
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
    bool native=fast(w);
    if(native) while(count<MAX_BLOCK) {
        r=fetch(e,pc+count*4,&w); if(r!=BB_STOP || !fast(w)) break;
        n+=lower(w,pc+count*4,code+n); ++count;
    }
    else count=1;
    size_t slot=e->next++ % e->slots; if(e->blocks[slot].valid) ++e->stats.evictions;
    struct block *b=&e->blocks[slot]; *b=(struct block){pc,(uint8_t)count,true,native};
    if(native) { code[n++]=0xd65f03c0; memcpy(e->rw+slot*SLOT,code,n*4); sys_icache_invalidate(e->rx+slot*SLOT,n*4); }
    ++e->stats.translations; *out=b; return BB_STOP;
}
bb_result bb_run(bb_engine *e, bb_state *s, uint64_t stop_pc, size_t budget) {
    if(!e || !s || e->poisoned) return BB_INTERNAL;
    while(s->pc!=stop_pc) {
        if(!budget) return BB_BUDGET;
        if (e->gate && s->pc==e->gate_address) {
            uint64_t lr=s->x[30];
            if (!e->gate(s,e->gate_opaque) || s->pc!=e->gate_address || s->x[30]!=lr) return BB_INTERNAL;
            s->pc=lr; --budget; continue;
        }
        struct block *b=lookup(e,s->pc); bb_result r;
        if(!b && (r=translate(e,s->pc,&b))!=BB_STOP) return r;
        bool stop_inside = stop_pc > s->pc && stop_pc - s->pc < (uint64_t)b->count * 4;
        if(b->native && b->count<=budget && !stop_inside) {
            size_t slot=(size_t)(b-e->blocks); ((void (*)(bb_state *))(void *)(e->rx+slot*SLOT))(s);
            s->pc+=(uint64_t)b->count*4; budget-=b->count; ++e->stats.native_blocks;
        } else {
            uint32_t w; if((r=fetch(e,s->pc,&w))!=BB_STOP) return r;
            if((r=step(e,s,w))!=BB_STOP) return r;
            --budget; ++e->stats.interpreted_instructions;
        }
    }
    return BB_STOP;
}
const char *bb_result_name(bb_result r) { switch(r) { case BB_STOP:return "stop"; case BB_BUDGET:return "budget"; case BB_UNSUPPORTED:return "unsupported"; case BB_MEMORY:return "memory"; case BB_ALIGNMENT:return "alignment"; case BB_INTERNAL:return "internal"; } return "unknown"; }
