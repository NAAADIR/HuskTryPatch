/* SPDX-License-Identifier: GPL-2.0-or-later */
#if defined(HUSK_OOP_IOS_DIAG) || defined(HUSK_OOP_DOMAIN_TEST)
#include "husk-oop-imports.h"
#include "husk-tl-ld.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

void *tl_bionic_find(const char *name);
void tl_set_guest_errno(int);

#define OOP_IMPORTS_MAX 512

typedef struct oop_import {
    oop_imports *owner;
    const char *name;
    void *fn;
    _Atomic unsigned calls;
    unsigned shape, arg;          /* adapter shape and its parameter */
    uint64_t token;               /* the gate address (when it differs from fn) */
} oop_import;

struct oop_imports {
    bb_engine *engine;
    oop_domain *domain;
    oop_import v[OOP_IMPORTS_MAX];   /* fixed: entry pointers handed to the domain must stay stable */
    size_t n;
    const char *_Atomic last;
    /* GL family */
    pthread_mutex_t gl_lock;
    void (*gl_get_integerv)(uint32_t, int32_t *);
    struct { uint32_t name; uint64_t guest; } gl_strings[8]; size_t gl_string_count;
    char gl_refusal[160];
};

/* Scan a guest C string, bounding the length; false if unterminated/unreadable. */
static bool guest_strnlen(bb_engine *e, uint64_t p, size_t limit, size_t *len) {
    for (size_t i=0;i<limit;i++) {
        unsigned char ch;
        if (p>UINT64_MAX-i || !bb_read(e,p+i,&ch,1)) return false;
        if (!ch) { *len=i; return true; }
    }
    return false;
}

/* ---- adapters. opaque is the oop_import* (stable). ---- */
/* Fortify (__*_chk): arg is 1 + the index of the guest's destination bound.
 * The bound is the guest's own; an overflow stops the guest, as bionic aborts. */
static bool mem_chk_ok(const oop_import *m, const bb_state *s, uint64_t needed) {
    return !m->arg || needed<=s->x[m->arg-1];
}

static bool imp_memcpy(const bb_state *s, uint64_t *result, void *opaque) {
    oop_import *m=opaque; bb_engine *e=m->owner->engine;
    uint64_t dst=s->x[0], src=s->x[1], n=s->x[2]; void *alias;
    if (!mem_chk_ok(m,s,n)) return false;
    if (!n) { *result=dst; ++m->calls; m->owner->last=m->name; return true; }   /* C: nothing is accessed */
    if (!bb_access(e,src,(size_t)n,BB_R) || !bb_host_data_alias(e,dst,(size_t)n,&alias)) return false;
    /* Overlap: bionic's arm64 memcpy (Arm optimized-routines) copies overlapping
     * ranges correctly, sharing memmove's entry, and Android code relies on it.
     * Give it memmove semantics through the one writable alias, so the host sees
     * the real overlap (two virtual aliases map one physical range). */
    if (dst<=src ? src-dst<n : dst-src<n) {
        void *in; if (!bb_host_data_alias(e,src,(size_t)n,&in)) return false;
        memmove(alias,in,(size_t)n); *result=dst; ++m->calls; m->owner->last=m->name; return true;
    }
    if (((void *(*)(void *,const void *,size_t))m->fn)(alias,(const void *)(uintptr_t)src,(size_t)n)!=alias) return false;
    *result=dst; ++m->calls; m->owner->last=m->name; return true;
}
static bool imp_memmove(const bb_state *s, uint64_t *result, void *opaque) {
    oop_import *m=opaque; bb_engine *e=m->owner->engine;
    uint64_t dst=s->x[0], src=s->x[1], n=s->x[2]; void *out,*in=NULL;
    if (!mem_chk_ok(m,s,n)) return false;
    if (!n) { *result=dst; ++m->calls; m->owner->last=m->name; return true; }
    if (!bb_access(e,src,(size_t)n,BB_R) || !bb_host_data_alias(e,dst,(size_t)n,&out)) return false;
    /* On overlap both operands must use the same writable alias so the host
     * memmove sees the real backing-store overlap. */
    bool overlap=dst<=src ? src-dst<n : dst-src<n;
    if (overlap && !bb_host_data_alias(e,src,(size_t)n,&in)) return false;
    if (!in) in=(void *)(uintptr_t)src;
    if (((void *(*)(void *,const void *,size_t))m->fn)(out,in,(size_t)n)!=out) return false;
    *result=dst; ++m->calls; m->owner->last=m->name; return true;
}
static bool imp_memset(const bb_state *s, uint64_t *result, void *opaque) {
    oop_import *m=opaque; bb_engine *e=m->owner->engine;
    uint64_t dst=s->x[0], n=s->x[2]; void *alias;
    if (!mem_chk_ok(m,s,n)) return false;
    if (!n) { *result=dst; ++m->calls; m->owner->last=m->name; return true; }
    if (!bb_host_data_alias(e,dst,(size_t)n,&alias)) return false;
    if (((void *(*)(void *,int,size_t))m->fn)(alias,(int)s->x[1],(size_t)n)!=alias) return false;
    *result=dst; ++m->calls; m->owner->last=m->name; return true;
}
static bool imp_memcmp(const bb_state *s, uint64_t *result, void *opaque) {
    oop_import *m=opaque; bb_engine *e=m->owner->engine;
    uint64_t a=s->x[0], b=s->x[1], n=s->x[2];
    if (n && (!bb_access(e,a,(size_t)n,BB_R) || !bb_access(e,b,(size_t)n,BB_R))) return false;
    /* read-only: the canonical guest view lives at the guest address */
    int r=n?((int (*)(const void *,const void *,size_t))m->fn)((const void *)(uintptr_t)a,(const void *)(uintptr_t)b,(size_t)n):0;
    *result=(uint32_t)(int32_t)r; ++m->calls; m->owner->last=m->name; return true;
}
static bool imp_strlen(const bb_state *s, uint64_t *result, void *opaque) {
    oop_import *m=opaque; bb_engine *e=m->owner->engine; size_t len;
    if (!guest_strnlen(e,s->x[0],1u<<24,&len) || !mem_chk_ok(m,s,len+1)) return false;
    size_t got=((size_t (*)(const char *))m->fn)((const char *)(uintptr_t)s->x[0]);
    if (got!=len) return false;
    *result=got; ++m->calls; m->owner->last=m->name; return true;
}
static bool imp_strnlen(const bb_state *s, uint64_t *result, void *opaque) {
    oop_import *m=opaque; bb_engine *e=m->owner->engine; uint64_t p=s->x[0], cap=s->x[1];
    /* Only the bytes up to the cap (or the NUL) need be readable. */
    size_t i=0; unsigned char ch=1;
    for (;i<cap;i++) { if (p>UINT64_MAX-i || !bb_read(e,p+i,&ch,1)) return false; if (!ch) break; }
    size_t got=((size_t (*)(const char *,size_t))m->fn)((const char *)(uintptr_t)p,(size_t)cap);
    if (got!=(i<cap?i:cap)) return false;
    *result=got; ++m->calls; m->owner->last=m->name; return true;
}
static bool imp_strcmp(const bb_state *s, uint64_t *result, void *opaque) {
    oop_import *m=opaque; bb_engine *e=m->owner->engine; size_t la,lb;
    if (!guest_strnlen(e,s->x[0],1u<<24,&la) || !guest_strnlen(e,s->x[1],1u<<24,&lb)) return false;
    int r=((int (*)(const char *,const char *))m->fn)((const char *)(uintptr_t)s->x[0],(const char *)(uintptr_t)s->x[1]);
    *result=(uint32_t)(int32_t)r; ++m->calls; m->owner->last=m->name; return true;
}
static bool imp_strncmp(const bb_state *s, uint64_t *result, void *opaque) {
    oop_import *m=opaque; bb_engine *e=m->owner->engine; uint64_t n=s->x[2];
    /* Compare reads at most n bytes or up to each NUL; bound both within n. */
    for (uint64_t side=0;side<2;side++) { uint64_t p=s->x[side]; unsigned char ch=1;
        for (uint64_t i=0;i<n && ch;i++) { if (p>UINT64_MAX-i || !bb_read(e,p+i,&ch,1)) return false; } }
    int r=n?((int (*)(const char *,const char *,size_t))m->fn)((const char *)(uintptr_t)s->x[0],(const char *)(uintptr_t)s->x[1],(size_t)n):0;
    *result=(uint32_t)(int32_t)r; ++m->calls; m->owner->last=m->name; return true;
}
/* Fortify guards: the real bionic forwards to the base routine after a bound
 * check. The extra trailing argument is the destination/buffer capacity; the
 * checked-access adapters above already bound every byte touched, so these
 * reuse the same adapter and ignore the guard argument (the host routine still
 * enforces it and aborts on a real overflow). */

typedef struct { const char *name; oop_host_callback fn; const char *impl; unsigned chk; } mem_entry;

oop_imports *oop_imports_create(bb_engine *engine, oop_domain *domain) {
    if (!engine || !domain) return NULL;
    oop_imports *b=calloc(1,sizeof(*b)); if (!b) return NULL;
    b->engine=engine; b->domain=domain;
    if (pthread_mutex_init(&b->gl_lock,NULL)) { free(b); return NULL; }
    return b;
}
void oop_imports_destroy(oop_imports *b) { if (!b) return; pthread_mutex_destroy(&b->gl_lock); free(b); }

int oop_imports_register_mem(oop_imports *b) {
    if (!b) return -1;
    static const mem_entry table[]={
        {"memcpy",imp_memcpy},{"memmove",imp_memmove},{"memset",imp_memset},{"memcmp",imp_memcmp},
        {"strlen",imp_strlen},{"strnlen",imp_strnlen},{"strcmp",imp_strcmp},{"strncmp",imp_strncmp},
        /* fortify: the gate is the _chk symbol; the work is the base routine after the guest's bound is checked */
        {"__memcpy_chk",imp_memcpy,"memcpy",4},{"__memmove_chk",imp_memmove,"memmove",4},{"__memset_chk",imp_memset,"memset",4},
        {"__strlen_chk",imp_strlen,"strlen",2},
    };
    int registered=0;
    for (size_t i=0;i<sizeof(table)/sizeof(table[0]);i++) {
        void *fn=tl_bionic_find(table[i].name), *impl=table[i].impl?tl_bionic_find(table[i].impl):fn;
        if (!fn || !impl) continue;        /* absent host symbol: skip, not fatal */
        if (b->n>=OOP_IMPORTS_MAX) return -1;
        /* The host may alias memcpy and memmove to one address; register the
         * overlap-safe adapter once for a shared address. */
        bool dup=false;
        for (size_t k=0;k<b->n;k++) if (b->v[k].token==(uintptr_t)fn) { dup=true; break; }
        if (dup) continue;
        oop_import *slot=&b->v[b->n];
        *slot=(oop_import){.owner=b,.name=table[i].name,.fn=impl,.arg=table[i].chk,.token=(uintptr_t)fn};
        if (!oop_domain_register_host(b->domain,(uintptr_t)fn,table[i].fn,slot)) return -1;
        ++b->n; ++registered;
    }
    return registered;
}

/* ===================================================================== GLES2
 * The GLES 2.0 entry points a guest imports, resolved to the same ANGLE
 * functions the loader bound (tl_bionic_find -> tl_egl_resolve). Calls run on
 * the calling host thread, so they use that thread's current context: the GL
 * thread's own. Guest pointers the GL reads are passed at their canonical,
 * host-readable guest address after a bounds check over every byte the call
 * can read; pointers GL writes go through the engine's writable alias, bounded
 * by the call's arguments, or through a host buffer copied back. A call whose
 * extent cannot be bounded is refused (the guest stops with the import named).
 *
 * Known, documented limit: a client-side vertex attribute array is checked
 * only to begin inside readable guest memory when it is specified; GL reads it
 * later, at draw time, through the read-only guest view (it cannot write it).
 */
enum { GLS_INT, GLS_FLOAT, GLS_GEN, GLS_DELETE, GLS_NAME, GLS_UNIFORM_LOCATION, GLS_BUFFER_DATA, GLS_BUFFER_SUB_DATA,
       GLS_DRAW_ELEMENTS, GLS_GET_INTEGERV, GLS_GET_FLOATV, GLS_GET_OBJECT_IV, GLS_INFO_LOG, GLS_GET_STRING,
       GLS_READ_PIXELS, GLS_SHADER_SOURCE, GLS_TEX_IMAGE_2D, GLS_UNIFORM_V, GLS_UNIFORM_MATRIX_V, GLS_VERTEX_ATTRIB_POINTER };
/* GLS_INT arg: bits 0-3 argument count, bit 4 returns a 32-bit value.
 * GLS_FLOAT arg: 1 f, 2 ffff, 3 if, 4 iff, 5 ifff, 6 iffff. */
#define GL_RET32 16u
static bool gl_refuse(oop_import *m, const char *why) {
    oop_imports *b=m->owner; pthread_mutex_lock(&b->gl_lock);
    snprintf(b->gl_refusal,sizeof(b->gl_refusal),"%s: %s",m->name,why);
    pthread_mutex_unlock(&b->gl_lock); return false;
}
static void gl_done(oop_import *m, uint64_t *result, uint64_t r) { *result=r; ++m->calls; m->owner->last=m->name; }
static bool gl_readable(bb_engine *e, uint64_t p, uint64_t n) { return !n || (p && n<=(UINT64_C(1)<<31) && bb_access(e,p,(size_t)n,BB_R)); }
static float gl_f(const bb_state *s, unsigned i) { uint32_t u=(uint32_t)s->v[i][0]; float f; memcpy(&f,&u,4); return f; }
static int32_t gl_query(oop_imports *b, uint32_t pname) { int32_t v=0; if (b->gl_get_integerv) b->gl_get_integerv(pname,&v); return v; }
/* Bytes per pixel for a format/type pair, 0 if unknown. */
static unsigned gl_pixel_bytes(uint32_t format, uint32_t type) {
    unsigned comps=format==0x1908||format==0x80E1?4:format==0x1907?3:format==0x190A?2:format==0x1906||format==0x1909?1:0;
    switch (type) {
    case 0x1401: return comps;                          /* UNSIGNED_BYTE */
    case 0x8363: return format==0x1907?2:0;             /* UNSIGNED_SHORT_5_6_5 */
    case 0x8033: case 0x8034: return format==0x1908?2:0; /* 4_4_4_4, 5_5_5_1 */
    case 0x1406: return comps*4;                        /* FLOAT */
    case 0x8D61: return comps*2;                        /* HALF_FLOAT_OES */
    default: return 0;
    }
}
/* Bytes GL touches for a w x h image at the pack/unpack alignment. */
static bool gl_image_bytes(oop_imports *b, int64_t w, int64_t h, uint32_t format, uint32_t type, uint32_t align_pname, uint64_t *n) {
    if (w<0 || h<0 || w>65536 || h>65536) return false;
    if (!w || !h) { *n=0; return true; }
    unsigned bpp=gl_pixel_bytes(format,type); if (!bpp) return false;
    int32_t align=gl_query(b,align_pname); if (align!=1 && align!=2 && align!=4 && align!=8) return false;
    uint64_t row=(uint64_t)w*bpp, stride=(row+(uint64_t)align-1)/(uint64_t)align*(uint64_t)align;
    *n=stride*(uint64_t)(h-1)+row; return true;
}
/* glGet*v: GL writes into a sentinel-filled host buffer; only the pname's
 * documented count is copied back, and a write past it refuses the call. */
static unsigned gl_get_count(oop_imports *b, uint32_t pname) {
    switch (pname) {
    case 0x846D: case 0x846E: case 0x0B70: case 0x0D3A: return 2;
    case 0x0BA2: case 0x0C10: case 0x0C22: case 0x0C23: case 0x8005: return 4;
    case 0x86A3: { int32_t c=gl_query(b,0x86A2); return c>=0 && c<4096 ? (unsigned)c : 0; }
    case 0x8DF8: { int32_t c=gl_query(b,0x8DF9); return c>=0 && c<4096 ? (unsigned)c : 0; }
    default: return 1;
    }
}
static bool gl_getv(oop_import *m, const bb_state *s, uint64_t *result, unsigned count, uint64_t ptr, bool object, uint64_t object_name) {
    bb_engine *e=m->owner->engine; void *alias; uint32_t pname=(uint32_t)(object?s->x[1]:s->x[0]);
    if (!count) { gl_done(m,result,0); return true; }   /* nothing to write */
    if (!ptr || !bb_host_data_alias(e,ptr,(size_t)count*4,&alias)) return gl_refuse(m,"output not writable guest memory");
    size_t cap=(size_t)count+64; uint32_t *tmp=malloc(cap*4); if (!tmp) return false;
    for (size_t i=0;i<cap;i++) tmp[i]=0xa5a5a5a5u;
    if (object) ((void (*)(uint32_t,uint32_t,void *))m->fn)((uint32_t)object_name,pname,tmp);
    else ((void (*)(uint32_t,void *))m->fn)(pname,tmp);
    bool over=false; for (size_t i=count;i<cap;i++) over|=tmp[i]!=0xa5a5a5a5u;
    if (over) { free(tmp); return gl_refuse(m,"GL wrote more values than the parameter's known count"); }
    memcpy(alias,tmp,(size_t)count*4); free(tmp); gl_done(m,result,0); return true;
}
static bool imp_gl(const bb_state *s, uint64_t *result, void *opaque) {
    oop_import *m=opaque; oop_imports *b=m->owner; bb_engine *e=b->engine; void *fn=m->fn;
    const uint64_t *x=s->x; void *alias=NULL; size_t len;
    switch (m->shape) {
    case GLS_INT: {
        uint64_t r=((uint64_t (*)(uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t))fn)(x[0],x[1],x[2],x[3],x[4],x[5],x[6],x[7]);
        gl_done(m,result,(m->arg&GL_RET32)?(uint32_t)r:0); return true; }
    case GLS_FLOAT:
        switch (m->arg) {
        case 1: ((void (*)(float))fn)(gl_f(s,0)); break;
        case 2: ((void (*)(float,float,float,float))fn)(gl_f(s,0),gl_f(s,1),gl_f(s,2),gl_f(s,3)); break;
        case 3: ((void (*)(int32_t,float))fn)((int32_t)x[0],gl_f(s,0)); break;
        case 4: ((void (*)(int32_t,float,float))fn)((int32_t)x[0],gl_f(s,0),gl_f(s,1)); break;
        case 5: ((void (*)(int32_t,float,float,float))fn)((int32_t)x[0],gl_f(s,0),gl_f(s,1),gl_f(s,2)); break;
        case 6: ((void (*)(int32_t,float,float,float,float))fn)((int32_t)x[0],gl_f(s,0),gl_f(s,1),gl_f(s,2),gl_f(s,3)); break;
        default: return false;
        }
        gl_done(m,result,0); return true;
    case GLS_GEN: case GLS_DELETE: {
        int32_t n=(int32_t)x[0]; if (n<0 || n>(1<<20)) return gl_refuse(m,"count out of range");
        void *p=(void *)(uintptr_t)x[1];
        if (n && m->shape==GLS_GEN) { if (!bb_host_data_alias(e,x[1],(size_t)n*4,&alias)) return gl_refuse(m,"names not writable"); p=alias; }
        if (n && m->shape==GLS_DELETE && !gl_readable(e,x[1],(uint64_t)n*4)) return gl_refuse(m,"names not readable");
        ((void (*)(int32_t,void *))fn)(n,p); gl_done(m,result,0); return true; }
    case GLS_NAME:   /* glBindAttribLocation(program, index, name) */
        if (!guest_strnlen(e,x[2],4096,&len)) return gl_refuse(m,"name not a guest string");
        ((void (*)(uint32_t,uint32_t,const char *))fn)((uint32_t)x[0],(uint32_t)x[1],(const char *)(uintptr_t)x[2]);
        gl_done(m,result,0); return true;
    case GLS_UNIFORM_LOCATION:
        if (!guest_strnlen(e,x[1],4096,&len)) return gl_refuse(m,"name not a guest string");
        gl_done(m,result,(uint32_t)((int32_t (*)(uint32_t,const char *))fn)((uint32_t)x[0],(const char *)(uintptr_t)x[1])); return true;
    case GLS_BUFFER_DATA:   /* (target, size, data, usage) */
        if ((int64_t)x[1]<0 || (x[2] && !gl_readable(e,x[2],x[1]))) return gl_refuse(m,"data not readable for size");
        ((void (*)(uint32_t,int64_t,const void *,uint32_t))fn)((uint32_t)x[0],(int64_t)x[1],(const void *)(uintptr_t)x[2],(uint32_t)x[3]);
        gl_done(m,result,0); return true;
    case GLS_BUFFER_SUB_DATA:   /* (target, offset, size, data) */
        if ((int64_t)x[2]<0 || !gl_readable(e,x[3],x[2])) return gl_refuse(m,"data not readable for size");
        ((void (*)(uint32_t,int64_t,int64_t,const void *))fn)((uint32_t)x[0],(int64_t)x[1],(int64_t)x[2],(const void *)(uintptr_t)x[3]);
        gl_done(m,result,0); return true;
    case GLS_DRAW_ELEMENTS: {   /* (mode, count, type, indices) */
        int32_t count=(int32_t)x[1]; uint32_t type=(uint32_t)x[2];
        unsigned size=type==0x1401?1:type==0x1403?2:type==0x1405?4:0;
        if (count<0 || !size) return gl_refuse(m,"count or index type");
        if (!gl_query(b,0x8895) && !gl_readable(e,x[3],(uint64_t)count*size)) return gl_refuse(m,"client indices not readable");
        ((void (*)(uint32_t,int32_t,uint32_t,const void *))fn)((uint32_t)x[0],count,type,(const void *)(uintptr_t)x[3]);
        gl_done(m,result,0); return true; }
    case GLS_GET_INTEGERV: case GLS_GET_FLOATV:
        return gl_getv(m,s,result,gl_get_count(b,(uint32_t)x[0]),x[1],false,0);
    case GLS_GET_OBJECT_IV:     /* glGetShaderiv / glGetProgramiv: one value in GLES 2 */
        return gl_getv(m,s,result,1,x[2],true,x[0]);
    case GLS_INFO_LOG: {        /* (object, bufSize, length*, infoLog*) */
        int32_t cap=(int32_t)x[1]; void *lenp=NULL, *log=NULL;
        if (cap<0 || cap>(1<<24)) return gl_refuse(m,"buffer size");
        if (x[2] && !bb_host_data_alias(e,x[2],4,&lenp)) return gl_refuse(m,"length not writable");
        if (cap && (!x[3] || !bb_host_data_alias(e,x[3],(size_t)cap,&log))) return gl_refuse(m,"log not writable");
        ((void (*)(uint32_t,int32_t,void *,void *))fn)((uint32_t)x[0],cap,lenp,log);
        gl_done(m,result,0); return true; }
    case GLS_GET_STRING: {
        /* The host string becomes a guest copy, made once per name. */
        uint32_t name=(uint32_t)x[0]; uint64_t guest=0;
        pthread_mutex_lock(&b->gl_lock);
        for (size_t i=0;i<b->gl_string_count;i++) if (b->gl_strings[i].name==name) guest=b->gl_strings[i].guest;
        pthread_mutex_unlock(&b->gl_lock);
        if (!guest) {
            const char *host=((const char *(*)(uint32_t))fn)(name);
            if (host) {
                size_t n=strnlen(host,1u<<16); if (n==1u<<16) return gl_refuse(m,"host string unbounded");
                guest=bb_heap_malloc(e,n+1); if (!guest || !bb_write(e,guest,host,n+1)) return gl_refuse(m,"guest copy");
                pthread_mutex_lock(&b->gl_lock);
                if (b->gl_string_count<8) b->gl_strings[b->gl_string_count++]=(typeof(b->gl_strings[0])){name,guest};
                pthread_mutex_unlock(&b->gl_lock);
            }
        }
        gl_done(m,result,guest); return true; }
    case GLS_READ_PIXELS: {     /* (x, y, w, h, format, type, pixels) */
        uint64_t n;
        if (!gl_image_bytes(b,(int32_t)x[2],(int32_t)x[3],(uint32_t)x[4],(uint32_t)x[5],0x0D05,&n)) return gl_refuse(m,"pixel extent");
        if (n && (!x[6] || !bb_host_data_alias(e,x[6],(size_t)n,&alias))) return gl_refuse(m,"pixels not writable");
        ((void (*)(int32_t,int32_t,int32_t,int32_t,uint32_t,uint32_t,void *))fn)((int32_t)x[0],(int32_t)x[1],(int32_t)x[2],(int32_t)x[3],(uint32_t)x[4],(uint32_t)x[5],alias);
        gl_done(m,result,0); return true; }
    case GLS_SHADER_SOURCE: {   /* (shader, count, strings, lengths) */
        int32_t count=(int32_t)x[1];
        if (count<0 || count>1024 || !gl_readable(e,x[2],(uint64_t)count*8) || (x[3] && !gl_readable(e,x[3],(uint64_t)count*4))) return gl_refuse(m,"string arrays");
        for (int32_t i=0;i<count;i++) { uint64_t p; int32_t l=-1;
            if (!bb_read(e,x[2]+(uint64_t)i*8,&p,8) || (x[3] && !bb_read(e,x[3]+(uint64_t)i*4,&l,4))) return false;
            if (l>=0 ? !gl_readable(e,p,(uint64_t)l) : !guest_strnlen(e,p,1u<<24,&len)) return gl_refuse(m,"source string"); }
        ((void (*)(uint32_t,int32_t,const void *,const void *))fn)((uint32_t)x[0],count,(const void *)(uintptr_t)x[2],(const void *)(uintptr_t)x[3]);
        gl_done(m,result,0); return true; }
    case GLS_TEX_IMAGE_2D: {    /* nine arguments: pixels is the first stack slot */
        uint64_t pixels, n;
        if (!bb_read(e,s->sp,&pixels,8)) return gl_refuse(m,"stack argument");
        if (!gl_image_bytes(b,(int32_t)x[3],(int32_t)x[4],(uint32_t)x[6],(uint32_t)x[7],0x0CF5,&n)) return gl_refuse(m,"pixel extent");
        if (pixels && !gl_readable(e,pixels,n)) return gl_refuse(m,"pixels not readable");
        ((void (*)(uint32_t,int32_t,int32_t,int32_t,int32_t,int32_t,uint32_t,uint32_t,const void *))fn)(
            (uint32_t)x[0],(int32_t)x[1],(int32_t)x[2],(int32_t)x[3],(int32_t)x[4],(int32_t)x[5],(uint32_t)x[6],(uint32_t)x[7],(const void *)(uintptr_t)pixels);
        gl_done(m,result,0); return true; }
    case GLS_UNIFORM_V: {       /* (location, count, values): arg = components */
        int32_t count=(int32_t)x[1];
        if (count<0 || !gl_readable(e,x[2],(uint64_t)count*m->arg*4)) return gl_refuse(m,"values not readable");
        ((void (*)(int32_t,int32_t,const void *))fn)((int32_t)x[0],count,(const void *)(uintptr_t)x[2]);
        gl_done(m,result,0); return true; }
    case GLS_UNIFORM_MATRIX_V: {   /* (location, count, transpose, values) */
        int32_t count=(int32_t)x[1];
        if (count<0 || !gl_readable(e,x[3],(uint64_t)count*m->arg*4)) return gl_refuse(m,"values not readable");
        ((void (*)(int32_t,int32_t,uint8_t,const void *))fn)((int32_t)x[0],count,(uint8_t)x[2],(const void *)(uintptr_t)x[3]);
        gl_done(m,result,0); return true; }
    case GLS_VERTEX_ATTRIB_POINTER:   /* (index, size, type, normalized, stride, pointer) */
        if ((int32_t)x[4]<0) return gl_refuse(m,"stride");
        if (!gl_query(b,0x8894) && x[5] && !gl_readable(e,x[5],1)) return gl_refuse(m,"client array outside guest memory");
        ((void (*)(uint32_t,int32_t,uint32_t,uint8_t,int32_t,const void *))fn)((uint32_t)x[0],(int32_t)x[1],(uint32_t)x[2],(uint8_t)x[3],(int32_t)x[4],(const void *)(uintptr_t)x[5]);
        gl_done(m,result,0); return true;
    default: return false;
    }
}
int oop_imports_register_gl(oop_imports *b) {
    if (!b) return -1;
    static const struct { const char *name; unsigned shape, arg; } table[]={
        {"glActiveTexture",GLS_INT,1},{"glAttachShader",GLS_INT,2},{"glBindBuffer",GLS_INT,2},{"glBindFramebuffer",GLS_INT,2},
        {"glBindRenderbuffer",GLS_INT,2},{"glBindTexture",GLS_INT,2},{"glBlendFunc",GLS_INT,2},
        {"glCheckFramebufferStatus",GLS_INT,1|GL_RET32},{"glClear",GLS_INT,1},{"glClearStencil",GLS_INT,1},
        {"glCompileShader",GLS_INT,1},{"glCreateProgram",GLS_INT,0|GL_RET32},{"glCreateShader",GLS_INT,1|GL_RET32},
        {"glDeleteProgram",GLS_INT,1},{"glDeleteShader",GLS_INT,1},{"glDepthFunc",GLS_INT,1},{"glDisable",GLS_INT,1},
        {"glDisableVertexAttribArray",GLS_INT,1},{"glDrawArrays",GLS_INT,3},{"glEnable",GLS_INT,1},
        {"glEnableVertexAttribArray",GLS_INT,1},{"glFramebufferRenderbuffer",GLS_INT,4},{"glFramebufferTexture2D",GLS_INT,5},
        {"glGenerateMipmap",GLS_INT,1},{"glGetError",GLS_INT,0|GL_RET32},{"glLinkProgram",GLS_INT,1},{"glPixelStorei",GLS_INT,2},
        {"glRenderbufferStorage",GLS_INT,4},{"glScissor",GLS_INT,4},{"glTexParameteri",GLS_INT,3},{"glUniform1i",GLS_INT,2},
        {"glUseProgram",GLS_INT,1},{"glViewport",GLS_INT,4},
        {"glLineWidth",GLS_FLOAT,1},{"glClearDepthf",GLS_FLOAT,1},{"glClearColor",GLS_FLOAT,2},{"glUniform1f",GLS_FLOAT,3},
        {"glUniform2f",GLS_FLOAT,4},{"glUniform3f",GLS_FLOAT,5},{"glUniform4f",GLS_FLOAT,6},
        {"glGenBuffers",GLS_GEN,0},{"glGenFramebuffers",GLS_GEN,0},{"glGenRenderbuffers",GLS_GEN,0},{"glGenTextures",GLS_GEN,0},
        {"glDeleteBuffers",GLS_DELETE,0},{"glDeleteFramebuffers",GLS_DELETE,0},{"glDeleteRenderbuffers",GLS_DELETE,0},{"glDeleteTextures",GLS_DELETE,0},
        {"glBindAttribLocation",GLS_NAME,0},{"glGetUniformLocation",GLS_UNIFORM_LOCATION,0},
        {"glBufferData",GLS_BUFFER_DATA,0},{"glBufferSubData",GLS_BUFFER_SUB_DATA,0},{"glDrawElements",GLS_DRAW_ELEMENTS,0},
        {"glGetIntegerv",GLS_GET_INTEGERV,0},{"glGetFloatv",GLS_GET_FLOATV,0},
        {"glGetShaderiv",GLS_GET_OBJECT_IV,0},{"glGetProgramiv",GLS_GET_OBJECT_IV,0},
        {"glGetShaderInfoLog",GLS_INFO_LOG,0},{"glGetProgramInfoLog",GLS_INFO_LOG,0},{"glGetString",GLS_GET_STRING,0},
        {"glReadPixels",GLS_READ_PIXELS,0},{"glShaderSource",GLS_SHADER_SOURCE,0},{"glTexImage2D",GLS_TEX_IMAGE_2D,0},
        {"glUniform2fv",GLS_UNIFORM_V,2},{"glUniform3fv",GLS_UNIFORM_V,3},{"glUniform4fv",GLS_UNIFORM_V,4},
        {"glUniformMatrix4fv",GLS_UNIFORM_MATRIX_V,16},{"glVertexAttribPointer",GLS_VERTEX_ATTRIB_POINTER,0},
    };
    b->gl_get_integerv=(void (*)(uint32_t,int32_t *))tl_bionic_find("glGetIntegerv");
    if (!b->gl_get_integerv) return 0;   /* no GLES library: nothing to register */
    int registered=0;
    for (size_t i=0;i<sizeof(table)/sizeof(table[0]);i++) {
        void *fn=tl_bionic_find(table[i].name);
        if (!fn) continue;
        if (b->n>=OOP_IMPORTS_MAX) return -1;
        oop_import *slot=&b->v[b->n];
        *slot=(oop_import){.owner=b,.token=(uintptr_t)fn,.name=table[i].name,.fn=fn,.shape=table[i].shape,.arg=table[i].arg};
        if (!oop_domain_register_host(b->domain,(uintptr_t)fn,imp_gl,slot)) return -1;
        ++b->n; ++registered;
    }
    return registered;
}
const char *oop_imports_refusal(oop_imports *b) { return b && b->gl_refusal[0] ? b->gl_refusal : NULL; }
/* ============================================== libc strings, math and time
 * Husk's bionic implementations, each through a typed shape. Strings are
 * passed at their canonical, host-readable guest address after a terminated,
 * bounded scan; anything written goes through the writable alias over exactly
 * the bytes the call writes. A pointer the host routine returns into its
 * argument is therefore already the guest's own address. Fortify (_chk)
 * variants enforce their bound here: an overflow stops the guest, as the real
 * one aborts. Float/double results go back in v0 (oop_domain_return_fp). */
enum { LS_STRCPY, LS_STRNCPY, LS_STRCAT, LS_STRCHR, LS_STR2, LS_STRN2, LS_MEMCHR, LS_STRDUP, LS_INT1, LS_ATO, LS_STRTO,
       LM_F1, LM_F2, LM_D1, LM_D2, LM_MODF, LM_FREXP, LM_SINCOS, LM_SINCOSF, LT_TIME, LT_CLOCK_GETTIME, LT_GETTIMEOFDAY, LT_DIFFTIME, LR_INT0, LR_VOID1, LR_RAND_R, LS_STRTOK, LS_STRTOK_R, LS_STRSEP, LT_TM_R, LT_TM_STATIC, LT_MKTIME, LT_STRFTIME };
/* struct tm: bionic's and Darwin's arm64 layouts agree (nine ints, long
 * tm_gmtoff, const char *tm_zone; 56 bytes). Only tm_zone needs a guest
 * value: a cached guest copy of the zone name. */
#define TM_BYTES 56u
#define TM_ZONE 48u
static pthread_mutex_t lt_lock=PTHREAD_MUTEX_INITIALIZER;
static struct { char name[16]; uint64_t guest; } lt_zones[16]; static size_t lt_nzones;
static uint64_t lt_static[2];   /* gmtime's and localtime's result buffers */
static bool lt_fix_zone(bb_engine *e, uint8_t *tm) {
    const char *z; memcpy(&z,tm+TM_ZONE,8); uint64_t g=0;
    if (z) {
        char name[16]={0}; strncpy(name,z,15);
        pthread_mutex_lock(&lt_lock);
        for (size_t i=0;i<lt_nzones;i++) if (!strcmp(lt_zones[i].name,name)) g=lt_zones[i].guest;
        if (!g && lt_nzones<16) { g=bb_heap_malloc(e,16); if (g && bb_write(e,g,name,16)) { memcpy(lt_zones[lt_nzones].name,name,16); lt_zones[lt_nzones++].guest=g; } else g=0; }
        pthread_mutex_unlock(&lt_lock);
        if (!g) return false;
    }
    memcpy(tm+TM_ZONE,&g,8); return true;
}
/* arg flags */
#define LA_CHK 1u      /* fortify bound in the trailing argument */
#define LA_PTR 2u      /* returns a pointer into an argument */
#define LA_SIZE 4u     /* returns size_t */
#define LA_FP 8u       /* returns double in v0 (LS_ATO/LS_STRTO) */
#define LA_F32 32u     /* with LA_FP: float */
static bool lc_str(bb_engine *e, uint64_t p, size_t *n) { return p && guest_strnlen(e,p,1u<<24,n); }
static bool lc_overlap(uint64_t a, uint64_t na, uint64_t b, uint64_t nb) { return a<b+nb && b<a+na; }
static double lc_d(const bb_state *s, unsigned i) { double d; memcpy(&d,&s->v[i][0],8); return d; }
static float lc_f(const bb_state *s, unsigned i) { uint32_t u=(uint32_t)s->v[i][0]; float f; memcpy(&f,&u,4); return f; }
static bool lc_ret_d(oop_import *m, double d) { uint64_t u; memcpy(&u,&d,8); return oop_domain_return_fp(m->owner->domain,u); }
static bool lc_ret_f(oop_import *m, float f) { uint32_t u; memcpy(&u,&f,4); return oop_domain_return_fp(m->owner->domain,u); }
static void lc_done(oop_import *m, uint64_t *result, uint64_t r) { *result=r; ++m->calls; m->owner->last=m->name; }
/* strtok/strtok_r/strsep run here over guest memory, with libc's exact
 * semantics: the host routines would write NULs through, and keep a pointer
 * into, the guest's read-only view. strtok's state is process-wide, as bionic's. */
static pthread_mutex_t lc_tok_lock=PTHREAD_MUTEX_INITIALIZER; static uint64_t lc_tok_last;
static bool lc_in(bb_engine *e, uint64_t delim, size_t dl, unsigned char ch) {
    for (size_t i=0;i<dl;i++) { unsigned char d; if (!bb_read(e,delim+i,&d,1)) return false; if (d==ch) return true; }
    return false;
}
/* One token from *p: NULL at end; *p becomes the rest (0 once exhausted). */
static bool lc_token(bb_engine *e, uint64_t *p, uint64_t delim, bool skip_leading, uint64_t *tok) {
    size_t dl; unsigned char ch; *tok=0;
    if (!guest_strnlen(e,delim,4096,&dl)) return false;
    if (!*p) return true;
    uint64_t q=*p;
    if (skip_leading) for (;;) { if (!bb_read(e,q,&ch,1)) return false; if (!ch) { *p=0; return true; } if (!lc_in(e,delim,dl,ch)) break; q++; }
    *tok=q;
    for (size_t n=0;n<(1u<<24);n++,q++) {
        if (!bb_read(e,q,&ch,1)) return false;
        if (!ch) { *p=0; return true; }
        if (lc_in(e,delim,dl,ch)) { unsigned char z=0; if (!bb_write(e,q,&z,1)) return false; *p=q+1; return true; }
    }
    return false;
}
static bool imp_libc(const bb_state *s, uint64_t *result, void *opaque) {
    oop_import *m=opaque; bb_engine *e=m->owner->engine; void *fn=m->fn; const uint64_t *x=s->x;
    size_t ls, ld; void *alias;
    switch (m->shape) {
    case LS_STRCPY: {           /* (dst, src[, dstlen]) */
        if (!lc_str(e,x[1],&ls) || ((m->arg&LA_CHK) && ls+1>x[2]) || lc_overlap(x[0],ls+1,x[1],ls+1) ||
            !bb_host_data_alias(e,x[0],ls+1,&alias)) return false;
        memcpy(alias,(const void *)(uintptr_t)x[1],ls+1); lc_done(m,result,x[0]); return true; }
    case LS_STRNCPY: {          /* (dst, src, n[, dstlen]): writes exactly n bytes */
        uint64_t n=x[2]; size_t i=0; unsigned char ch=1;
        if (n>(1u<<24) || ((m->arg&LA_CHK) && n>x[3])) return false;
        for (;i<n;i++) { if (!bb_read(e,x[1]+i,&ch,1)) return false; if (!ch) break; }
        if (n && (lc_overlap(x[0],n,x[1],i<n?i+1:n) || !bb_host_data_alias(e,x[0],(size_t)n,&alias))) return false;
        if (n) { memcpy(alias,(const void *)(uintptr_t)x[1],i); memset((char *)alias+i,0,(size_t)n-i); }
        lc_done(m,result,x[0]); return true; }
    case LS_STRCAT: {           /* (dst, src) */
        if (!lc_str(e,x[0],&ld) || !lc_str(e,x[1],&ls) || lc_overlap(x[0],ld+ls+1,x[1],ls+1) ||
            !bb_host_data_alias(e,x[0]+ld,ls+1,&alias)) return false;
        memcpy(alias,(const void *)(uintptr_t)x[1],ls+1); lc_done(m,result,x[0]); return true; }
    case LS_STRCHR: {           /* strchr/strrchr(s, c[, slen]) */
        if (!lc_str(e,x[0],&ls) || ((m->arg&LA_CHK) && ls+1>x[2])) return false;
        lc_done(m,result,(uintptr_t)((char *(*)(const char *,int))fn)((const char *)(uintptr_t)x[0],(int)x[1])); return true; }
    case LS_STR2: {             /* two strings: strstr, strpbrk, strspn, strcspn, strcasecmp */
        if (!lc_str(e,x[0],&ls) || !lc_str(e,x[1],&ld)) return false;
        uint64_t r=((uint64_t (*)(const char *,const char *))fn)((const char *)(uintptr_t)x[0],(const char *)(uintptr_t)x[1]);
        lc_done(m,result,(m->arg&(LA_PTR|LA_SIZE))?r:(uint32_t)r); return true; }
    case LS_STRN2: {            /* strncasecmp(a, b, n): reads at most n of each */
        for (int k=0;k<2;k++) { unsigned char ch=1; for (uint64_t i=0;i<x[2] && ch;i++) if (!bb_read(e,x[k]+i,&ch,1)) return false; }
        lc_done(m,result,(uint32_t)((int (*)(const char *,const char *,size_t))fn)((const char *)(uintptr_t)x[0],(const char *)(uintptr_t)x[1],(size_t)x[2])); return true; }
    case LS_MEMCHR:             /* memchr/memrchr(s, c, n) */
        if (x[2] && !bb_access(e,x[0],(size_t)x[2],BB_R)) return false;
        lc_done(m,result,x[2]?(uintptr_t)((void *(*)(const void *,int,size_t))fn)((const void *)(uintptr_t)x[0],(int)x[1],(size_t)x[2]):0); return true;
    case LS_STRDUP: {           /* the copy lives in the guest heap */
        if (!lc_str(e,x[0],&ls)) return gl_refuse(m,"source is not a terminated guest string");
        uint64_t g=bb_heap_malloc(e,ls+1);
        if (!g) tl_set_guest_errno(12 /* ENOMEM */);
        /* guest to guest: through the new block's writable alias (a fresh block never overlaps its source) */
        if (g) { if (!bb_host_data_alias(e,g,ls+1,&alias)) return gl_refuse(m,"copy into the guest heap");
                 memcpy(alias,(const void *)(uintptr_t)x[0],ls+1); }
        lc_done(m,result,g); return true; }
    case LS_INT1:               /* ctype and friends: int -> int */
        lc_done(m,result,(uint32_t)((int (*)(int))fn)((int)x[0])); return true;
    case LS_ATO:                /* atoi/atol/atof(s) */
        if (!lc_str(e,x[0],&ls)) return false;
        if (m->arg&LA_FP) { if (!lc_ret_d(m,((double (*)(const char *))fn)((const char *)(uintptr_t)x[0]))) return false; lc_done(m,result,0); }
        else lc_done(m,result,(uint64_t)((long (*)(const char *))fn)((const char *)(uintptr_t)x[0]));
        return true;
    case LS_STRTO: {            /* strtol(s, end, base) / strtod(s, end) */
        char *end=NULL; void *endp=NULL;
        if (!lc_str(e,x[0],&ls) || (x[1] && !bb_host_data_alias(e,x[1],8,&endp))) return false;
        if ((m->arg&LA_FP) && (m->arg&LA_F32)) { if (!lc_ret_f(m,((float (*)(const char *,char **))fn)((const char *)(uintptr_t)x[0],&end))) return false; *result=0; }
        else if (m->arg&LA_FP) { if (!lc_ret_d(m,((double (*)(const char *,char **))fn)((const char *)(uintptr_t)x[0],&end))) return false; *result=0; }
        else *result=(uint64_t)((long (*)(const char *,char **,int))fn)((const char *)(uintptr_t)x[0],&end,(int)x[2]);
        /* end points into the guest string at its guest address */
        if (endp) { uint64_t g=(uintptr_t)end; memcpy(endp,&g,8); }
        ++m->calls; m->owner->last=m->name; return true; }
    case LM_F1: if (!lc_ret_f(m,((float (*)(float))fn)(lc_f(s,0)))) return false; lc_done(m,result,0); return true;
    case LM_F2: if (!lc_ret_f(m,((float (*)(float,float))fn)(lc_f(s,0),lc_f(s,1)))) return false; lc_done(m,result,0); return true;
    case LM_D1: if (!lc_ret_d(m,((double (*)(double))fn)(lc_d(s,0)))) return false; lc_done(m,result,0); return true;
    case LM_D2: if (!lc_ret_d(m,((double (*)(double,double))fn)(lc_d(s,0),lc_d(s,1)))) return false; lc_done(m,result,0); return true;
    case LM_MODF: {             /* modf(d, double *ip) */
        double ip; if (!bb_host_data_alias(e,x[0],8,&alias)) return false;
        if (!lc_ret_d(m,((double (*)(double,double *))fn)(lc_d(s,0),&ip))) return false;
        memcpy(alias,&ip,8); lc_done(m,result,0); return true; }
    case LM_FREXP: {            /* frexp(d, int *exp) */
        int ex; if (!bb_host_data_alias(e,x[0],4,&alias)) return false;
        if (!lc_ret_d(m,((double (*)(double,int *))fn)(lc_d(s,0),&ex))) return false;
        memcpy(alias,&ex,4); lc_done(m,result,0); return true; }
    case LM_SINCOS: case LM_SINCOSF: {   /* (a, *sin, *cos) */
        void *ps,*pc; size_t n=m->shape==LM_SINCOS?8:4;
        if (!bb_host_data_alias(e,x[0],n,&ps) || !bb_host_data_alias(e,x[1],n,&pc)) return false;
        if (n==8) { double a,b; ((void (*)(double,double *,double *))fn)(lc_d(s,0),&a,&b); memcpy(ps,&a,8); memcpy(pc,&b,8); }
        else { float a,b; ((void (*)(float,float *,float *))fn)(lc_f(s,0),&a,&b); memcpy(ps,&a,4); memcpy(pc,&b,4); }
        lc_done(m,result,0); return true; }
    case LT_TIME: {             /* time(t*) */
        int64_t t=((int64_t (*)(void *))fn)(NULL);
        if (x[0]) { if (!bb_host_data_alias(e,x[0],8,&alias)) return false; memcpy(alias,&t,8); }
        lc_done(m,result,(uint64_t)t); return true; }
    case LT_CLOCK_GETTIME: {    /* (clock, struct timespec *) : two 64-bit fields on arm64 */
        uint64_t ts[2];
        if (!bb_host_data_alias(e,x[1],16,&alias)) return false;
        int r=((int (*)(int,void *))fn)((int)x[0],ts);
        if (!r) memcpy(alias,ts,16);
        lc_done(m,result,(uint32_t)r); return true; }
    case LT_GETTIMEOFDAY: {     /* (struct timeval *, struct timezone *) */
        uint64_t tv[2]; int32_t tz[2]; void *tza=NULL;
        if ((x[0] && !bb_host_data_alias(e,x[0],16,&alias)) || (x[1] && !bb_host_data_alias(e,x[1],8,&tza))) return false;
        int r=((int (*)(void *,void *))fn)(tv,x[1]?tz:NULL);
        if (!r && x[0]) memcpy(alias,tv,16);
        if (!r && tza) memcpy(tza,tz,8);
        lc_done(m,result,(uint32_t)r); return true; }
    case LS_STRTOK: {
        pthread_mutex_lock(&lc_tok_lock);
        uint64_t p=x[0]?x[0]:lc_tok_last, tok; bool ok=lc_token(e,&p,x[1],true,&tok);
        if (ok) lc_tok_last=p;
        pthread_mutex_unlock(&lc_tok_lock);
        if (!ok) return false; lc_done(m,result,tok); return true; }
    case LS_STRTOK_R: case LS_STRSEP: {   /* strtok_r(s, delim, char **save) / strsep(char **sp, delim) */
        uint64_t slot=m->shape==LS_STRTOK_R?x[2]:x[0], delim=m->shape==LS_STRTOK_R?x[1]:x[1], p, tok;
        if (!bb_host_data_alias(e,slot,8,&alias)) return false;
        memcpy(&p,alias,8); if (m->shape==LS_STRTOK_R && x[0]) p=x[0];
        if (!lc_token(e,&p,delim,m->shape==LS_STRTOK_R,&tok)) return false;
        memcpy(alias,&p,8); lc_done(m,result,tok); return true; }
    case LT_TM_R: case LT_TM_STATIC: { /* gmtime_r/localtime_r(const time_t *, struct tm *) / gmtime/localtime(const time_t *) */
        int64_t t; uint8_t tm[TM_BYTES];
        if (!bb_read(e,x[0],&t,8)) return false;
        uint64_t dst=x[1];
        if (m->shape==LT_TM_STATIC) {
            unsigned k=m->arg; pthread_mutex_lock(&lt_lock); if (!lt_static[k]) lt_static[k]=bb_heap_malloc(e,TM_BYTES); dst=lt_static[k]; pthread_mutex_unlock(&lt_lock);
            if (!dst) return false;
        }
        void *(*conv)(const int64_t *,void *)=(void *(*)(const int64_t *,void *))tl_bionic_find(m->arg?"localtime_r":"gmtime_r");
        if (!conv || !bb_host_data_alias(e,dst,TM_BYTES,&alias)) return false;
        if (!conv(&t,tm)) { lc_done(m,result,0); return true; }
        if (!lt_fix_zone(e,tm)) return false;
        memcpy(alias,tm,TM_BYTES); lc_done(m,result,dst); return true; }
    case LT_MKTIME: {           /* mktime(struct tm *): normalizes in place */
        uint8_t tm[TM_BYTES];
        if (!bb_read(e,x[0],tm,TM_BYTES) || !bb_host_data_alias(e,x[0],TM_BYTES,&alias)) return false;
        memset(tm+TM_ZONE,0,8);
        int64_t r=((int64_t (*)(void *))fn)(tm);
        if (!lt_fix_zone(e,tm)) return false;
        memcpy(alias,tm,TM_BYTES); lc_done(m,result,(uint64_t)r); return true; }
    case LT_STRFTIME: {         /* (buf, max, fmt, const struct tm *): the guest's tm_zone is a guest string */
        uint8_t tm[TM_BYTES]; uint64_t zone;
        if (x[1]>(1u<<20) || !lc_str(e,x[2],&ls) || !bb_read(e,x[3],tm,TM_BYTES) || (x[1] && !bb_host_data_alias(e,x[0],(size_t)x[1],&alias))) return false;
        memcpy(&zone,tm+TM_ZONE,8); if (zone && !lc_str(e,zone,&ld)) return false;
        lc_done(m,result,((size_t (*)(char *,size_t,const char *,const void *))fn)(alias,(size_t)x[1],(const char *)(uintptr_t)x[2],tm)); return true; }
    case LR_INT0:               /* rand(), random() */
        lc_done(m,result,(uint64_t)((long (*)(void))fn)()); return true;
    case LR_VOID1:              /* srand(seed), srandom(seed) */
        ((void (*)(unsigned))fn)((unsigned)x[0]); lc_done(m,result,0); return true;
    case LR_RAND_R: {           /* rand_r(unsigned *seed): the seed is guest state, updated in place */
        unsigned seed;
        if (!bb_host_data_alias(e,x[0],4,&alias)) return false;
        memcpy(&seed,alias,4); int r=((int (*)(unsigned *))fn)(&seed); memcpy(alias,&seed,4);
        lc_done(m,result,(uint32_t)r); return true; }
    case LT_DIFFTIME:
        if (!lc_ret_d(m,((double (*)(int64_t,int64_t))fn)((int64_t)x[0],(int64_t)x[1]))) return false;
        lc_done(m,result,0); return true;
    default: return false;
    }
}
int oop_imports_register_libc(oop_imports *b) {
    if (!b) return -1;
    static const struct { const char *name; unsigned shape, arg; const char *impl; } table[]={
        {"strtoll",LS_STRTO,0,NULL},{"strtoull",LS_STRTO,0,NULL},{"strtof",LS_STRTO,LA_FP|LA_F32,NULL},
        /* bionic's *_l conversions ignore the locale: the guest's handle is never used */
        {"strtoll_l",LS_STRTO,0,"strtoll"},{"strtoull_l",LS_STRTO,0,"strtoull"},
        {"strcpy",LS_STRCPY,0},{"__strcpy_chk",LS_STRCPY,LA_CHK},{"strncpy",LS_STRNCPY,0},{"__strncpy_chk",LS_STRNCPY,LA_CHK},
        {"strcat",LS_STRCAT,0},{"strchr",LS_STRCHR,0},{"__strchr_chk",LS_STRCHR,LA_CHK},{"strrchr",LS_STRCHR,0},
        {"strstr",LS_STR2,LA_PTR},{"strpbrk",LS_STR2,LA_PTR},{"strspn",LS_STR2,LA_SIZE},{"strcspn",LS_STR2,LA_SIZE},
        {"strcasecmp",LS_STR2,0},{"strncasecmp",LS_STRN2,0},{"memchr",LS_MEMCHR,0},{"memrchr",LS_MEMCHR,0},{"strdup",LS_STRDUP,0},
        {"tolower",LS_INT1,0},{"toupper",LS_INT1,0},{"isalnum",LS_INT1,0},{"isalpha",LS_INT1,0},{"isgraph",LS_INT1,0},
        {"islower",LS_INT1,0},{"isprint",LS_INT1,0},{"isspace",LS_INT1,0},{"isupper",LS_INT1,0},{"isxdigit",LS_INT1,0},
        {"atoi",LS_ATO,0},{"atol",LS_ATO,0},{"atof",LS_ATO,LA_FP},{"strtol",LS_STRTO,0},{"strtod",LS_STRTO,LA_FP},
        {"acosf",LM_F1,0},{"asinf",LM_F1,0},{"atanf",LM_F1,0},{"cosf",LM_F1,0},{"sinf",LM_F1,0},{"tanf",LM_F1,0},
        {"expf",LM_F1,0},{"exp2f",LM_F1,0},{"logf",LM_F1,0},{"atan2f",LM_F2,0},{"fmodf",LM_F2,0},{"powf",LM_F2,0},
        {"ceil",LM_D1,0},{"floor",LM_D1,0},{"cos",LM_D1,0},{"sin",LM_D1,0},{"sqrt",LM_D1,0},{"exp",LM_D1,0},
        {"log",LM_D1,0},{"log10",LM_D1,0},{"atan2",LM_D2,0},{"fmod",LM_D2,0},{"pow",LM_D2,0},
        {"modf",LM_MODF,0},{"frexp",LM_FREXP,0},{"sincos",LM_SINCOS,0},{"sincosf",LM_SINCOSF,0},
        {"strtok",LS_STRTOK,0,NULL},{"strtok_r",LS_STRTOK_R,0,NULL},{"strsep",LS_STRSEP,0,NULL},
        {"rand",LR_INT0,0,NULL},{"random",LR_INT0,0,NULL},{"srand",LR_VOID1,0,NULL},{"srandom",LR_VOID1,0,NULL},{"rand_r",LR_RAND_R,0,NULL},
        {"gmtime_r",LT_TM_R,0,NULL},{"localtime_r",LT_TM_R,1,NULL},{"gmtime",LT_TM_STATIC,0,NULL},{"localtime",LT_TM_STATIC,1,NULL},
        {"mktime",LT_MKTIME,0,NULL},{"strftime",LT_STRFTIME,0,NULL},
        {"time",LT_TIME,0},{"clock_gettime",LT_CLOCK_GETTIME,0},{"gettimeofday",LT_GETTIMEOFDAY,0},{"difftime",LT_DIFFTIME,0},
    };
    int registered=0;
    for (size_t i=0;i<sizeof(table)/sizeof(table[0]);i++) {
        void *fn=tl_bionic_find(table[i].name), *impl=table[i].impl?tl_bionic_find(table[i].impl):fn;
        if (!fn || !impl) continue;
        bool dup=false; for (size_t k=0;k<b->n;k++) if (b->v[k].token==(uintptr_t)fn) { dup=true; break; }
        if (dup) continue;   /* an alias of an import already bridged */
        if (b->n>=OOP_IMPORTS_MAX) return -1;
        oop_import *slot=&b->v[b->n];
        *slot=(oop_import){.owner=b,.token=(uintptr_t)fn,.name=table[i].name,.fn=impl,.shape=table[i].shape,.arg=table[i].arg};
        if (!oop_domain_register_host(b->domain,(uintptr_t)fn,imp_libc,slot)) return -1;
        ++b->n; ++registered;
    }
    return registered;
}
/* ====================================================== formatted output
 * A guest-varargs formatter: the guest's format is parsed here and each
 * argument is taken from the guest's own registers/stack (a variadic call) or
 * from its AAPCS64 va_list, never handed to a host va_arg. Each conversion is
 * formatted alone by the host snprintf. %s strings are scanned within guest
 * memory (to their precision); %n and long double are refused. */
typedef struct { bb_engine *e; uint64_t gr[8]; unsigned ngr, gi; uint64_t vr[8]; unsigned nvr, vi; uint64_t stack;
                 bool va; uint64_t va_stack, gr_top, vr_top; int32_t gr_offs, vr_offs; } pf_args;
static bool pf_next(pf_args *a, bool fp, uint64_t *out) {
    if (a->va) {
        uint64_t at;
        if (!fp && a->gr_offs<0) { if (a->gr_offs<-64 || a->gr_offs%8) return false; at=a->gr_top-(uint64_t)-(int64_t)a->gr_offs; a->gr_offs+=8; }
        else if (fp && a->vr_offs<0) { if (a->vr_offs<-128 || a->vr_offs%16) return false; at=a->vr_top-(uint64_t)-(int64_t)a->vr_offs; a->vr_offs+=16; }
        else { if (a->va_stack&7) return false; at=a->va_stack; a->va_stack+=8; }
        return bb_read(a->e,at,out,8);
    }
    if (!fp && a->gi<a->ngr) { *out=a->gr[a->gi++]; return true; }
    if (fp && a->vi<a->nvr) { *out=a->vr[a->vi++]; return true; }
    bool ok=bb_read(a->e,a->stack,out,8); a->stack+=8; return ok;
}
static bool pf_from_regs(pf_args *a, bb_engine *e, const bb_state *s, unsigned first_gpr) {
    memset(a,0,sizeof(*a)); a->e=e;
    for (unsigned i=first_gpr;i<8;i++) a->gr[a->ngr++]=s->x[i];
    for (unsigned i=0;i<8;i++) a->vr[a->nvr++]=s->v[i][0];
    a->stack=s->sp; return true;
}
static bool pf_from_va(pf_args *a, bb_engine *e, uint64_t va) {
    memset(a,0,sizeof(*a)); a->e=e; a->va=true;
    struct { uint64_t stack, gr_top, vr_top; int32_t gr_offs, vr_offs; } v;
    if (!va || !bb_read(e,va,&v,sizeof(v))) return false;
    a->va_stack=v.stack; a->gr_top=v.gr_top; a->vr_top=v.vr_top; a->gr_offs=v.gr_offs; a->vr_offs=v.vr_offs; return true;
}
typedef struct { char *p; size_t n, cap; } pf_out;
static bool pf_put(pf_out *o, const char *s, size_t n) {
    if (o->n+n+1>o->cap) { size_t c=o->cap?o->cap:256; while (o->n+n+1>c) c*=2; if (c>(1u<<26)) return false;
        char *q=realloc(o->p,c); if (!q) return false; o->p=q; o->cap=c; }
    memcpy(o->p+o->n,s,n); o->n+=n; o->p[o->n]=0; return true;
}
static int (*pf_snprintf)(char *, size_t, const char *, ...);
static bool pf_format(bb_engine *e, uint64_t fmt, pf_args *a, pf_out *o) {
    size_t flen; if (!guest_strnlen(e,fmt,1u<<20,&flen)) return false;
    const char *f=(const char *)(uintptr_t)fmt; char spec[64], buf[512];
    for (size_t i=0;i<flen;) {
        if (f[i]!='%') { size_t j=i; while (j<flen && f[j]!='%') j++; if (!pf_put(o,f+i,j-i)) return false; i=j; continue; }
        size_t st=i++; if (i<flen && f[i]=='%') { if (!pf_put(o,"%",1)) return false; i++; continue; }
        int width=-1, prec=-1; bool star_w=false, star_p=false;
        while (i<flen && strchr("-+ #0'",f[i])) i++;
        if (i<flen && f[i]=='*') { star_w=true; i++; } else while (i<flen && f[i]>='0' && f[i]<='9') { width=(width<0?0:width)*10+(f[i++]-'0'); if (width>4096) return false; }
        if (i<flen && f[i]=='.') { i++; prec=0; if (i<flen && f[i]=='*') { star_p=true; i++; } else while (i<flen && f[i]>='0' && f[i]<='9') prec=prec*10+(f[i++]-'0'); }
        size_t lm=i; while (i<flen && strchr("hlzjtL",f[i])) i++;
        if (i>=flen || i-st+2>sizeof(spec)) return false;
        char conv=f[i++]; size_t sl=i-st; memcpy(spec,f+st,sl); spec[sl]=0;
        bool longlen=false; for (size_t k=lm;k<i-1;k++) { if (f[k]=='L') return false; if (strchr("lzjt",f[k])) longlen=true; }
        uint64_t v, wv=0, pv=0;
        if (star_w && !pf_next(a,false,&wv)) return false;
        if (star_p) { if (!pf_next(a,false,&pv)) return false; prec=(int32_t)pv; }
        int n;
        #define PF1(arg) (star_w&&star_p ? pf_snprintf(buf,sizeof(buf),spec,(int)wv,(int)pv,arg) : star_w ? pf_snprintf(buf,sizeof(buf),spec,(int)wv,arg) : \
                          star_p ? pf_snprintf(buf,sizeof(buf),spec,(int)pv,arg) : pf_snprintf(buf,sizeof(buf),spec,arg))
        switch (conv) {
        case 'd': case 'i': if (!pf_next(a,false,&v)) return false; n=longlen?PF1((long long)v):PF1((int)v); break;
        case 'u': case 'x': case 'X': case 'o': if (!pf_next(a,false,&v)) return false; n=longlen?PF1((unsigned long long)v):PF1((unsigned)v); break;
        case 'c': if (!pf_next(a,false,&v)) return false; n=PF1((int)v); break;
        case 'p': if (!pf_next(a,false,&v)) return false; n=PF1((void *)(uintptr_t)v); break;
        case 'f': case 'F': case 'e': case 'E': case 'g': case 'G': case 'a': case 'A': { double d;
            if (!pf_next(a,true,&v)) return false; memcpy(&d,&v,8); n=PF1(d); break; }
        case 's': { size_t len=0; if (longlen || !pf_next(a,false,&v)) return false;   /* %ls: wide, refused */
            if (!v) { n=PF1("(null)"); break; }
            if (prec>4096) return false;
            if (prec>=0) { unsigned char ch=1; for (;len<(size_t)prec;len++) { if (!bb_read(e,v+len,&ch,1)) return false; if (!ch) break; } }
            else if (!guest_strnlen(e,v,1u<<24,&len)) return false;
            if (len+(width>0?(size_t)width:0)+64>sizeof(buf)) {   /* long strings: copy directly, honouring precision only */
                if (star_w || width>0) return false;
                if (!pf_put(o,(const char *)(uintptr_t)v,len)) return false; continue; }
            n=PF1((const char *)(uintptr_t)v); break; }
        default: return false;   /* %n, wide conversions and anything unknown */
        }
        #undef PF1
        if (n<0) return false;
        if ((size_t)n>=sizeof(buf)) return false;
        if (!pf_put(o,buf,(size_t)n)) return false;
    }
    return true;
}
enum { LP_SNPRINTF, LP_SPRINTF, LP_VSNPRINTF, LP_VSPRINTF, LP_VSNPRINTF_CHK, LP_VSPRINTF_CHK, LP_VASPRINTF, LP_LOG, LP_SSCANF, LP_VSSCANF };
/* sscanf over guest memory: each conversion is scanned alone by the host
 * sscanf with a trailing %n (the exact input consumed); results are written
 * to the guest's destination pointers at the width the length modifier
 * implies. %s/%[/%c are bounded by the remaining input. Returns the C value. */
static bool sc_scan(bb_engine *e, uint64_t str, uint64_t fmt, pf_args *a, int *count_out) {
    size_t ilen, flen; if (!guest_strnlen(e,str,1u<<20,&ilen) || !guest_strnlen(e,fmt,4096,&flen)) return false;
    const char *in=(const char *)(uintptr_t)str, *f=(const char *)(uintptr_t)fmt; size_t pos=0; int count=0; bool any_input=false;
    for (size_t i=0;i<flen;) {
        unsigned char fc=(unsigned char)f[i];
        if (fc==' '||(fc>='\t'&&fc<='\r')) { while (pos<ilen && (in[pos]==' '||(in[pos]>='\t'&&in[pos]<='\r'))) pos++; i++; continue; }
        if (fc!='%' || (i+1<flen && f[i+1]=='%')) { size_t k=fc=='%'?2:1; if (pos>=ilen || in[pos]!=(fc=='%'?'%':f[i])) break; pos++; i+=k; continue; }
        size_t st=i++; bool suppress=false; int width=0;
        if (i<flen && f[i]=='*') { suppress=true; i++; }
        while (i<flen && f[i]>='0' && f[i]<='9') width=width*10+(f[i++]-'0');
        size_t lm=i; while (i<flen && strchr("hlLzjt",f[i])) i++;
        if (i>=flen) return false;
        size_t convpos=i; char conv=f[i++]; size_t setend=i;
        if (conv=='[') { if (setend<flen && f[setend]=='^') setend++; if (setend<flen && f[setend]==']') setend++; while (setend<flen && f[setend]!=']') setend++; if (setend>=flen) return false; i=setend+1; }
        char mods[4]={0}; if (i-st>200 || convpos-lm>=sizeof(mods)) return false; memcpy(mods,f+lm,convpos-lm);
        if (conv=='n') { if (!suppress) { uint64_t p; void *al; if (!pf_next(a,false,&p) || !bb_host_data_alias(e,p,4,&al)) return false; int32_t v=(int32_t)pos; memcpy(al,&v,4); } continue; }
        if (conv!='c' && conv!='[') { size_t q=pos; while (q<ilen && (in[q]==' '||(in[q]>='\t'&&in[q]<='\r'))) q++; if (q>=ilen) { if (!any_input && !count) { *count_out=-1; return true; } break; } }
        if (pos>=ilen && !count && !any_input) { *count_out=-1; return true; }
        char spec[260]; size_t sl=i-st; memcpy(spec,f+st,sl); memcpy(spec+sl,"%n",3);
        int consumed=-1, r; size_t rem=ilen-pos;
        bool ll=strstr(mods,"ll")||strchr(mods,'j')||strchr(mods,'z')||strchr(mods,'t')||(strchr(mods,'l')&&conv!='f'&&conv!='e'&&conv!='g'&&conv!='a'), dbl=strchr(mods,'l')!=NULL;
        if (strchr(mods,'L')) return false;
        if (suppress) { r=sscanf(in+pos,spec,&consumed); if (consumed<0) break; pos+=(size_t)consumed; any_input=true; continue; }
        uint64_t dst; void *al; if (!pf_next(a,false,&dst)) return false;
        switch (conv) {
        case 'd': case 'i': case 'u': case 'x': case 'X': case 'o': {
            long long v=0; char spec2[264]; size_t k=0; /* scan into long long, store at the guest width */
            spec2[k++]='%'; if (width) k+=(size_t)snprintf(spec2+k,sizeof(spec2)-k,"%d",width); spec2[k++]='l'; spec2[k++]='l'; spec2[k++]=conv; memcpy(spec2+k,"%n",3);
            r=sscanf(in+pos,spec2,&v,&consumed); if (r<1 || consumed<0) goto done;
            size_t bytes=strstr(mods,"hh")?1:strchr(mods,'h')?2:ll?8:4;
            if (!bb_host_data_alias(e,dst,bytes,&al)) return false; memcpy(al,&v,bytes); break; }
        case 'f': case 'e': case 'g': case 'E': case 'G': case 'a': {
            double v=0; r=sscanf(in+pos,dbl?"%lf%n":"%lf%n",&v,&consumed);
            if (width) { char sp[32]; snprintf(sp,sizeof(sp),"%%%dlf%%n",width); r=sscanf(in+pos,sp,&v,&consumed); }
            if (r<1 || consumed<0) goto done;
            if (dbl) { if (!bb_host_data_alias(e,dst,8,&al)) return false; memcpy(al,&v,8); }
            else { float fv=(float)v; if (!bb_host_data_alias(e,dst,4,&al)) return false; memcpy(al,&fv,4); }
            break; }
        case 's': case '[': case 'c': {
            if (strchr(mods,'l')) return false;   /* wide */
            size_t cap=conv=='c'?(size_t)(width?width:1):rem+1; char *tmp=calloc(cap+1,1); if (!tmp) return false;
            r=sscanf(in+pos,spec,tmp,&consumed);
            if (r<1 || consumed<0) { free(tmp); goto done; }
            size_t n=conv=='c'?cap:strnlen(tmp,cap)+1;
            if (!bb_host_data_alias(e,dst,n,&al)) { free(tmp); return false; } memcpy(al,tmp,n); free(tmp); break; }
        default: return false;
        }
        pos+=(size_t)consumed; count++; any_input=true;
    }
done:
    *count_out=count; return true;
}
/* Write the formatted result into a guest buffer of `cap` bytes (C semantics:
 * truncate, always terminate when cap > 0, return the full length). */
static bool pf_emit(bb_engine *e, uint64_t dst, uint64_t cap, const pf_out *o) {
    if (!cap) return true;
    size_t n=o->n<cap-1?o->n:(size_t)cap-1; void *alias;
    if (!bb_host_data_alias(e,dst,n+1,&alias)) return false;
    if (n) memcpy(alias,o->p,n); ((char *)alias)[n]=0; return true;
}
static bool imp_printf(const bb_state *s, uint64_t *result, void *opaque) {
    oop_import *m=opaque; bb_engine *e=m->owner->engine; const uint64_t *x=s->x; pf_args a; pf_out o={0}; bool ok=false;
    switch (m->shape) {
    case LP_SNPRINTF:      ok=pf_from_regs(&a,e,s,3) && pf_format(e,x[2],&a,&o) && x[1]<=(1u<<30) && pf_emit(e,x[0],x[1],&o); break;
    case LP_SPRINTF:       ok=pf_from_regs(&a,e,s,2) && pf_format(e,x[1],&a,&o) && pf_emit(e,x[0],o.n+1,&o); break;
    case LP_VSNPRINTF:     ok=pf_from_va(&a,e,x[3]) && pf_format(e,x[2],&a,&o) && x[1]<=(1u<<30) && pf_emit(e,x[0],x[1],&o); break;
    case LP_VSPRINTF:      ok=pf_from_va(&a,e,x[2]) && pf_format(e,x[1],&a,&o) && pf_emit(e,x[0],o.n+1,&o); break;
    case LP_VSNPRINTF_CHK: /* (buf, n, flag, buflen, fmt, va): n must fit buflen, as bionic aborts */
        ok=x[1]<=x[3] && pf_from_va(&a,e,x[5]) && pf_format(e,x[4],&a,&o) && x[1]<=(1u<<30) && pf_emit(e,x[0],x[1],&o); break;
    case LP_VSPRINTF_CHK:  /* (buf, flag, buflen, fmt, va) */
        ok=pf_from_va(&a,e,x[4]) && pf_format(e,x[3],&a,&o) && o.n+1<=x[2] && pf_emit(e,x[0],o.n+1,&o); break;
    case LP_VASPRINTF: {   /* (char **out, fmt, va): the result lives in the guest heap */
        void *outp; ok=x[0] && bb_host_data_alias(e,x[0],8,&outp) && pf_from_va(&a,e,x[2]) && pf_format(e,x[1],&a,&o);
        if (ok) { uint64_t g=bb_heap_malloc(e,o.n+1); ok=g && bb_write(e,g,o.p?o.p:"",o.n+1); if (ok) memcpy(outp,&g,8); }
        break; }
    case LP_SSCANF: case LP_VSSCANF: {   /* (str, fmt, ...) / (str, fmt, va_list) */
        int n=0; ok=(m->shape==LP_SSCANF?pf_from_regs(&a,e,s,2):pf_from_va(&a,e,x[2])) && sc_scan(e,x[0],x[1],&a,&n);
        if (ok) { *result=(uint32_t)n; ++m->calls; m->owner->last=m->name; }
        free(o.p); return ok; }
    case LP_LOG: {         /* __android_log_print(prio, tag, fmt, ...): to Husk's log */
        size_t tl; ok=(!x[1] || guest_strnlen(e,x[1],256,&tl)) && pf_from_regs(&a,e,s,3) && pf_format(e,x[2],&a,&o);
        if (ok) { void tl_log_line(const char *, ...); tl_log_line("[guest %s] %s",x[1]?(const char *)(uintptr_t)x[1]:"",o.p?o.p:""); }
        break; }
    }
    if (ok) { *result=m->shape==LP_LOG?1:(uint32_t)(int32_t)o.n; ++m->calls; m->owner->last=m->name; }
    free(o.p); return ok;
}
int oop_imports_register_printf(oop_imports *b) {
    if (!b) return -1;
    pf_snprintf=snprintf;
    static const struct { const char *name; unsigned shape; } table[]={
        {"snprintf",LP_SNPRINTF},{"sprintf",LP_SPRINTF},{"vsnprintf",LP_VSNPRINTF},{"vsprintf",LP_VSPRINTF},
        {"__vsnprintf_chk",LP_VSNPRINTF_CHK},{"__vsprintf_chk",LP_VSPRINTF_CHK},{"vasprintf",LP_VASPRINTF},{"__android_log_print",LP_LOG},
        {"sscanf",LP_SSCANF},{"vsscanf",LP_VSSCANF},
    };
    int registered=0;
    for (size_t i=0;i<sizeof(table)/sizeof(table[0]);i++) {
        void *fn=tl_bionic_find(table[i].name);
        if (!fn) continue;
        if (b->n>=OOP_IMPORTS_MAX) return -1;
        oop_import *slot=&b->v[b->n];
        *slot=(oop_import){.owner=b,.token=(uintptr_t)fn,.name=table[i].name,.fn=fn,.shape=table[i].shape};
        if (!oop_domain_register_host(b->domain,(uintptr_t)fn,imp_printf,slot)) return -1;
        ++b->n; ++registered;
    }
    return registered;
}
/* ============================================================ files
 * Husk's bionic stdio and fd calls (Android path mapping, Linux struct stat,
 * Linux open flags are all theirs). A guest FILE* is an opaque host handle:
 * only the standard streams and handles this bridge returned are accepted,
 * and the guest never dereferences one (it is not guest memory). Data buffers
 * are bounded by the call's arguments and written through the writable alias.
 * A guest buffer handed to setbuf/setvbuf is refused unless NULL: the host
 * would keep writing into it after the call. */
#define OOP_FILES_MAX 256
enum { LF_FOPEN, LF_FDOPEN, LF_FCLOSE, LF_FREAD, LF_FWRITE, LF_FGETS, LF_FPUTS, LF_FPUTC, LF_GETC, LF_UNGETC, LF_FILE_INT,
       LF_FFLUSH, LF_FSEEK, LF_FTELL, LF_SETBUF, LF_FPRINTF, LF_VFPRINTF, LF_OPEN, LF_READ, LF_READ_CHK, LF_WRITE,
       LF_INT_FD, LF_LSEEK, LF_FSTAT, LF_STAT, LF_ACCESS, LF_PATH1, LF_PATH2, LF_OPENDIR, LF_READDIR, LF_CLOSEDIR };
static pthread_mutex_t lf_lock=PTHREAD_MUTEX_INITIALIZER;
static uint64_t lf_files[OOP_FILES_MAX]; static size_t lf_count;
static uint64_t lf_std[3];
static bool lf_known(uint64_t f) {
    if (!f) return false;
    for (int i=0;i<3;i++) if (lf_std[i]==f) return true;
    pthread_mutex_lock(&lf_lock); bool k=false; for (size_t i=0;i<lf_count && !k;i++) k=lf_files[i]==f; pthread_mutex_unlock(&lf_lock);
    return k;
}
static bool lf_track(uint64_t f) {
    if (!f) return true;
    pthread_mutex_lock(&lf_lock); bool ok=lf_count<OOP_FILES_MAX; if (ok) lf_files[lf_count++]=f; pthread_mutex_unlock(&lf_lock);
    return ok;
}
static void lf_untrack(uint64_t f) {
    pthread_mutex_lock(&lf_lock);
    for (size_t i=0;i<lf_count;i++) if (lf_files[i]==f) { lf_files[i]=lf_files[--lf_count]; break; }
    pthread_mutex_unlock(&lf_lock);
}
#define LINUX_STAT_BYTES 128u
/* DIR* handles, each with a guest-heap copy of its current entry: Husk's
 * readdir returns a Linux-layout struct dirent in host memory. */
#define LINUX_DIRENT_BYTES 280u
static struct { uint64_t dir, entry; } lf_dirs[64]; static size_t lf_ndirs;
static uint64_t lf_dir_entry(uint64_t d) {
    pthread_mutex_lock(&lf_lock); uint64_t g=0; for (size_t i=0;i<lf_ndirs;i++) if (lf_dirs[i].dir==d) g=lf_dirs[i].entry; pthread_mutex_unlock(&lf_lock);
    return g;
}
static bool imp_file(const bb_state *s, uint64_t *result, void *opaque) {
    oop_import *m=opaque; bb_engine *e=m->owner->engine; void *fn=m->fn; const uint64_t *x=s->x; size_t l1,l2; void *alias=NULL;
    uint64_t r=0;
    switch (m->shape) {
    case LF_FOPEN:
        if (!lc_str(e,x[0],&l1) || !lc_str(e,x[1],&l2)) return false;
        r=(uintptr_t)((void *(*)(const char *,const char *))fn)((const char *)(uintptr_t)x[0],(const char *)(uintptr_t)x[1]);
        if (!lf_track(r)) { ((int (*)(void *))tl_bionic_find("fclose"))((void *)(uintptr_t)r); r=0; }
        break;
    case LF_FDOPEN:
        if (!lc_str(e,x[1],&l2)) return false;
        r=(uintptr_t)((void *(*)(int,const char *))fn)((int)x[0],(const char *)(uintptr_t)x[1]);
        if (!lf_track(r)) { ((int (*)(void *))tl_bionic_find("fclose"))((void *)(uintptr_t)r); r=0; }
        break;
    case LF_FCLOSE:
        if (!lf_known(x[0])) return false;
        lf_untrack(x[0]); r=(uint32_t)((int (*)(void *))fn)((void *)(uintptr_t)x[0]); break;
    case LF_FREAD: case LF_FWRITE: {   /* (ptr, size, n, FILE) */
        uint64_t size=x[1], n=x[2];
        if (!lf_known(x[3]) || (size && n>UINT64_MAX/size) || size*n>(UINT64_C(1)<<31)) return false;
        void *p=(void *)(uintptr_t)x[0];
        if (size*n) { if (m->shape==LF_FREAD) { if (!bb_host_data_alias(e,x[0],(size_t)(size*n),&alias)) return false; p=alias; }
                      else if (!bb_access(e,x[0],(size_t)(size*n),BB_R)) return false; }
        r=((size_t (*)(void *,size_t,size_t,void *))fn)(p,(size_t)size,(size_t)n,(void *)(uintptr_t)x[3]); break; }
    case LF_FGETS: {                   /* (buf, n, FILE) */
        int32_t n=(int32_t)x[1];
        if (!lf_known(x[2]) || n<=0 || n>(1<<24) || !bb_host_data_alias(e,x[0],(size_t)n,&alias)) return false;
        r=((char *(*)(char *,int,void *))fn)(alias,n,(void *)(uintptr_t)x[2]) ? x[0] : 0; break; }
    case LF_FPUTS:
        if (!lc_str(e,x[0],&l1) || !lf_known(x[1])) return false;
        r=(uint32_t)((int (*)(const char *,void *))fn)((const char *)(uintptr_t)x[0],(void *)(uintptr_t)x[1]); break;
    case LF_FPUTC: case LF_UNGETC:     /* (c, FILE) */
        if (!lf_known(x[1])) return false;
        r=(uint32_t)((int (*)(int,void *))fn)((int)x[0],(void *)(uintptr_t)x[1]); break;
    case LF_GETC: case LF_FILE_INT:    /* getc/fgetc/feof/ferror/fileno(FILE) */
        if (!lf_known(x[0])) return false;
        r=(uint32_t)((int (*)(void *))fn)((void *)(uintptr_t)x[0]); break;
    case LF_FFLUSH:                    /* NULL flushes every stream */
        if (x[0] && !lf_known(x[0])) return false;
        r=(uint32_t)((int (*)(void *))fn)((void *)(uintptr_t)x[0]); break;
    case LF_FSEEK:                     /* fseek/fseeko(FILE, off, whence) */
        if (!lf_known(x[0])) return false;
        r=(uint32_t)((int (*)(void *,long,int))fn)((void *)(uintptr_t)x[0],(long)x[1],(int)x[2]); break;
    case LF_FTELL:
        if (!lf_known(x[0])) return false;
        r=(uint64_t)((long (*)(void *))fn)((void *)(uintptr_t)x[0]); break;
    case LF_SETBUF:                    /* setbuf(FILE, NULL) only */
        if (!lf_known(x[0]) || x[1]) return false;
        ((void (*)(void *,void *))fn)((void *)(uintptr_t)x[0],NULL); break;
    case LF_FPRINTF: case LF_VFPRINTF: {   /* formatted by the guest-varargs formatter, then written */
        pf_args a; pf_out o={0};
        if (!lf_known(x[0])) return false;
        bool ok=(m->shape==LF_FPRINTF ? pf_from_regs(&a,e,s,2) : pf_from_va(&a,e,x[2])) && pf_format(e,x[1],&a,&o);
        if (ok && o.n) ok=((size_t (*)(const void *,size_t,size_t,void *))tl_bionic_find("fwrite"))(o.p,1,o.n,(void *)(uintptr_t)x[0])==o.n;
        r=ok?(uint32_t)o.n:(uint32_t)-1; free(o.p); break; }
    case LF_OPEN:                      /* open(path, flags, mode) / __open_2(path, flags) */
        if (!lc_str(e,x[0],&l1)) return false;
        r=(uint32_t)((int (*)(const char *,int,int))fn)((const char *)(uintptr_t)x[0],(int)x[1],(int)x[2]); break;
    case LF_READ: case LF_READ_CHK: {  /* read(fd, buf, n[, buflen]) */
        if (x[2]>(UINT64_C(1)<<31) || (m->shape==LF_READ_CHK && x[2]>x[3])) return false;
        if (x[2] && !bb_host_data_alias(e,x[1],(size_t)x[2],&alias)) return false;
        r=(uint64_t)((long (*)(int,void *,size_t))fn)((int)x[0],alias,(size_t)x[2]); break; }
    case LF_WRITE:
        if (x[2]>(UINT64_C(1)<<31) || (x[2] && !bb_access(e,x[1],(size_t)x[2],BB_R))) return false;
        r=(uint64_t)((long (*)(int,const void *,size_t))fn)((int)x[0],(const void *)(uintptr_t)x[1],(size_t)x[2]); break;
    case LF_INT_FD:                    /* close(fd) */
        r=(uint32_t)((int (*)(int))fn)((int)x[0]); break;
    case LF_LSEEK:
        r=(uint64_t)((long (*)(int,long,int))fn)((int)x[0],(long)x[1],(int)x[2]); break;
    case LF_FSTAT:                     /* fstat(fd, struct stat *): Linux arm64 layout */
        if (!bb_host_data_alias(e,x[1],LINUX_STAT_BYTES,&alias)) return false;
        r=(uint32_t)((int (*)(int,void *))fn)((int)x[0],alias); break;
    case LF_STAT:
        if (!lc_str(e,x[0],&l1) || !bb_host_data_alias(e,x[1],LINUX_STAT_BYTES,&alias)) return false;
        r=(uint32_t)((int (*)(const char *,void *))fn)((const char *)(uintptr_t)x[0],alias); break;
    case LF_ACCESS:                    /* access/chmod(path, int) */
        if (!lc_str(e,x[0],&l1)) return false;
        r=(uint32_t)((int (*)(const char *,int))fn)((const char *)(uintptr_t)x[0],(int)x[1]); break;
    case LF_PATH1:                     /* remove(path) */
        if (!lc_str(e,x[0],&l1)) return false;
        r=(uint32_t)((int (*)(const char *))fn)((const char *)(uintptr_t)x[0]); break;
    case LF_PATH2:                     /* rename(a, b) */
        if (!lc_str(e,x[0],&l1) || !lc_str(e,x[1],&l2)) return false;
        r=(uint32_t)((int (*)(const char *,const char *))fn)((const char *)(uintptr_t)x[0],(const char *)(uintptr_t)x[1]); break;
    case LF_OPENDIR: {
        if (!lc_str(e,x[0],&l1)) return false;
        r=(uintptr_t)((void *(*)(const char *))fn)((const char *)(uintptr_t)x[0]);
        if (!r) break;
        uint64_t g=bb_heap_malloc(e,LINUX_DIRENT_BYTES);
        pthread_mutex_lock(&lf_lock); bool ok=g && lf_ndirs<64; if (ok) { lf_dirs[lf_ndirs].dir=r; lf_dirs[lf_ndirs++].entry=g; } pthread_mutex_unlock(&lf_lock);
        if (!ok) { if (g) bb_heap_free(e,g); ((int (*)(void *))tl_bionic_find("closedir"))((void *)(uintptr_t)r); r=0; tl_set_guest_errno(24 /* EMFILE */); }
        break; }
    case LF_READDIR: {
        uint64_t g=lf_dir_entry(x[0]); if (!g) return false;
        const void *ent=((void *(*)(void *))fn)((void *)(uintptr_t)x[0]);
        if (ent && !bb_write(e,g,ent,LINUX_DIRENT_BYTES)) return false;
        r=ent?g:0; break; }
    case LF_CLOSEDIR: {
        uint64_t g=0;
        pthread_mutex_lock(&lf_lock);
        for (size_t i=0;i<lf_ndirs;i++) if (lf_dirs[i].dir==x[0]) { g=lf_dirs[i].entry; lf_dirs[i]=lf_dirs[--lf_ndirs]; break; }
        pthread_mutex_unlock(&lf_lock);
        if (!g) return false;
        r=(uint32_t)((int (*)(void *))fn)((void *)(uintptr_t)x[0]); bb_heap_free(e,g); break; }
    default: return false;
    }
    *result=r; ++m->calls; m->owner->last=m->name; return true;
}
int oop_imports_register_files(oop_imports *b) {
    if (!b) return -1;
    const char *std_names[3]={"stdin","stdout","stderr"};
    for (int i=0;i<3;i++) { void **p=tl_bionic_find(std_names[i]); lf_std[i]=p?(uintptr_t)*p:0; }
    static const struct { const char *name; unsigned shape; } table[]={
        {"fopen",LF_FOPEN},{"fopen64",LF_FOPEN},{"fdopen",LF_FDOPEN},{"fclose",LF_FCLOSE},{"fread",LF_FREAD},{"fwrite",LF_FWRITE},
        {"fgets",LF_FGETS},{"fputs",LF_FPUTS},{"fputc",LF_FPUTC},{"ungetc",LF_UNGETC},{"getc",LF_GETC},{"fgetc",LF_GETC},
        {"feof",LF_FILE_INT},{"ferror",LF_FILE_INT},{"fileno",LF_FILE_INT},{"fflush",LF_FFLUSH},
        {"fseek",LF_FSEEK},{"fseeko",LF_FSEEK},{"fseeko64",LF_FSEEK},{"ftell",LF_FTELL},{"ftello",LF_FTELL},{"ftello64",LF_FTELL},
        {"setbuf",LF_SETBUF},{"fprintf",LF_FPRINTF},{"vfprintf",LF_VFPRINTF},
        {"open",LF_OPEN},{"__open_2",LF_OPEN},{"read",LF_READ},{"__read_chk",LF_READ_CHK},{"write",LF_WRITE},{"close",LF_INT_FD},
        {"lseek",LF_LSEEK},{"fstat",LF_FSTAT},{"stat",LF_STAT},{"access",LF_ACCESS},{"chmod",LF_ACCESS},
        {"remove",LF_PATH1},{"rename",LF_PATH2},
        {"opendir",LF_OPENDIR},{"readdir",LF_READDIR},{"readdir64",LF_READDIR},{"closedir",LF_CLOSEDIR},
    };
    int registered=0;
    for (size_t i=0;i<sizeof(table)/sizeof(table[0]);i++) {
        void *fn=tl_bionic_find(table[i].name);
        if (!fn) continue;
        bool dup=false; for (size_t k=0;k<b->n;k++) if (b->v[k].token==(uintptr_t)fn) { dup=true; break; }
        if (dup) continue;   /* fopen64 is fopen: one gate */
        if (b->n>=OOP_IMPORTS_MAX) return -1;
        oop_import *slot=&b->v[b->n];
        *slot=(oop_import){.owner=b,.token=(uintptr_t)fn,.name=table[i].name,.fn=fn,.shape=table[i].shape};
        if (!oop_domain_register_host(b->domain,(uintptr_t)fn,imp_file,slot)) return -1;
        ++b->n; ++registered;
    }
    return registered;
}
unsigned oop_imports_calls_named(const oop_imports *b, const char *name) {
    unsigned t=0; if (b) for (size_t i=0;i<b->n;i++) if (!strcmp(b->v[i].name,name)) t+=b->v[i].calls; return t;
}
/* __errno: the guest thread's own errno word, kept coherent by the domain. */
static bool imp_errno(const bb_state *s, uint64_t *result, void *opaque) {
    oop_import *m=opaque; uint64_t slot=s->tpidr_el0+m->arg;
    if (!bb_access(m->owner->engine,slot,4,BB_R|BB_W)) return false;
    *result=slot; ++m->calls; m->owner->last=m->name; return true;
}
int oop_imports_register_errno(oop_imports *b, uint64_t tls_offset) {
    if (!b) return -1;
    void *fn=tl_bionic_find("__errno");
    if (!fn) return 0;
    if (b->n>=OOP_IMPORTS_MAX || !oop_domain_set_errno(b->domain,(int *(*)(void))fn,tls_offset)) return -1;
    oop_import *slot=&b->v[b->n];
    *slot=(oop_import){.owner=b,.token=(uintptr_t)fn,.name="__errno",.fn=fn,.arg=(unsigned)tls_offset};
    if (!oop_domain_register_host(b->domain,(uintptr_t)fn,imp_errno,slot)) return -1;
    ++b->n; return 1;
}
/* Data imports: rebind the GOT slots of host-bound objects the guest reads
 * itself to guest-resident copies, before any guest code runs. Only objects
 * whose value is fixed and copyable are rebound; the rest stay host-bound and
 * are counted (a guest dereference of one stops with a memory fault). */
/* ========================================================== runtime
 * The generic runtime imports every guest library reaches, moved here from
 * the research harness: the guest heap (any thread attached to the domain),
 * bionic mutex/cond objects through Husk's shim (always on the writable
 * alias), syscall(gettid) only, arc4random, sigset edits, getenv (a guest
 * copy), strtoul and wcrtomb. */
enum { LRT_MALLOC, LRT_FREE, LRT_CALLOC, LRT_REALLOC, LRT_SYNC40, LRT_SYNC48, LRT_GETTID, LRT_RANDOM, LRT_SIGFILL, LRT_SIGDEL,
       LRT_GETENV, LRT_STRTOUL, LRT_WCRTOMB, LRT_KEY_CREATE, LRT_KEY_DELETE, LRT_GETSPECIFIC, LRT_SETSPECIFIC, LRT_SYNC, LRT_STRERROR, LRT_STRERROR_R, LRT_INT, LRT_NANOSLEEP, LRT_SIGACTION, LRT_SIGNAL };
/* Guest signal dispositions are guest state: bionic's 64-bit struct sigaction
 * (32 bytes) per signal, returned as oldact. The host's process-wide
 * dispositions are never changed, and guest handlers are not invoked (signals
 * are not delivered into guest code; Husk's sockets never raise SIGPIPE). */
#define GUEST_SIGACTION 32u
static pthread_mutex_t rt_sig_lock=PTHREAD_MUTEX_INITIALIZER; static uint8_t rt_sigact[65][GUEST_SIGACTION];
static pthread_mutex_t rt_err_lock=PTHREAD_MUTEX_INITIALIZER; static uint64_t rt_err_copy[256];
/* LRT_SYNC arg: bionic object sizes of up to three pointer arguments (bits 0-7, 8-15, 16-23; 0 = a plain
 * integer argument); bit 24/25: the second/third pointer may be NULL. */
#define RT_SYNC(a,b,c,flags) ((a)|((b)<<8)|((c)<<16)|(flags))
#define RT_OPT1 (1u<<24)
#define RT_OPT2 (1u<<25)
/* Guest pthread keys (bionic pthread_key_t is an int) mapped to host keys: a
 * value is per host thread, which is per guest thread. A guest destructor is
 * recorded but not run at thread exit (host code cannot call guest code there). */
#define OOP_KEYS 256
static pthread_mutex_t rt_key_lock=PTHREAD_MUTEX_INITIALIZER;
static struct { bool used; pthread_key_t key; uint64_t destructor; } rt_keys[OOP_KEYS];
static bool rt_key(uint64_t k, pthread_key_t *out) {
    pthread_mutex_lock(&rt_key_lock); bool ok=k<OOP_KEYS && rt_keys[k].used; if (ok) *out=rt_keys[k].key; pthread_mutex_unlock(&rt_key_lock); return ok;
}
static bool imp_runtime(const bb_state *s, uint64_t *result, void *opaque) {
    oop_import *m=opaque; oop_imports *b=m->owner; bb_engine *e=b->engine; void *fn=m->fn; const uint64_t *x=s->x; void *alias=NULL;
    uint64_t r=0;
    switch (m->shape) {
    case LRT_MALLOC:
        if (!oop_domain_thread_owns(b->domain,s->tpidr_el0)) return false;
        r=bb_heap_malloc(e,(size_t)x[0]); if (!r) tl_set_guest_errno(12); break;
    case LRT_FREE:
        if (!oop_domain_thread_owns(b->domain,s->tpidr_el0) || !bb_heap_free(e,x[0])) return false; break;
    case LRT_CALLOC: {
        if (!oop_domain_thread_owns(b->domain,s->tpidr_el0)) return false;
        size_t count=(size_t)x[0], size=(size_t)x[1];
        if (size && count>SIZE_MAX/size) { tl_set_guest_errno(12); break; }
        size_t n=count*size; r=bb_heap_malloc(e,n);
        if (!r) tl_set_guest_errno(12);
        else if (n) { if (!bb_host_data_alias(e,r,n,&alias)) return false; memset(alias,0,n); }
        break; }
    case LRT_REALLOC:
        if (!oop_domain_thread_owns(b->domain,s->tpidr_el0) || !bb_heap_realloc(e,x[0],(size_t)x[1],&r)) return false;
        if (!r && (x[1] || !x[0])) tl_set_guest_errno(12);
        break;
    case LRT_SYNC40: case LRT_SYNC48:   /* pthread_mutex_* (40 bytes) / pthread_cond_* (48 bytes) */
        if (!bb_host_data_alias(e,x[0],m->shape==LRT_SYNC40?40:48,&alias)) return false;
        r=(uint32_t)((int (*)(void *))fn)(alias); break;
    case LRT_GETTID:                    /* syscall: Linux AArch64 gettid (178) only */
        if (x[0]!=178) return false;
        r=(uint64_t)((long (*)(long,long,long,long,long,long,long))fn)((long)x[0],(long)x[1],(long)x[2],(long)x[3],(long)x[4],(long)x[5],(long)x[6]); break;
    case LRT_RANDOM: r=((uint32_t (*)(void))fn)(); break;
    case LRT_SIGFILL:
        if (!bb_host_data_alias(e,x[0],8,&alias)) return false;
        r=(uint32_t)((int (*)(void *))fn)(alias); break;
    case LRT_SIGDEL:
        if (!bb_host_data_alias(e,x[0],8,&alias)) return false;
        r=(uint32_t)((int (*)(void *,int))fn)(alias,(int)x[1]); break;
    case LRT_GETENV: {                  /* the value is copied into the guest heap */
        size_t len; if (!guest_strnlen(e,x[0],4096,&len)) return false;
        const char *v=((const char *(*)(const char *))fn)((const char *)(uintptr_t)x[0]);
        if (v) { size_t n=strnlen(v,1u<<20); if (n==(1u<<20)) return false;
            r=bb_heap_malloc(e,n+1); if (!r || !bb_write(e,r,v,n+1)) return false; }
        break; }
    case LRT_STRTOUL: {                 /* end points into the guest string */
        size_t n; char *end=NULL; void *endp=NULL;
        if (!guest_strnlen(e,x[0],1u<<20,&n) || (x[1] && !bb_host_data_alias(e,x[1],8,&endp))) return false;
        r=((unsigned long (*)(const char *,char **,int))fn)((const char *)(uintptr_t)x[0],&end,(int)x[2]);
        if (endp) { if ((uintptr_t)end<x[0] || (uintptr_t)end-x[0]>n) return false; uint64_t g=(uintptr_t)end; memcpy(endp,&g,8); }
        break; }
    case LRT_WCRTOMB: {                 /* Husk's shim ignores mbstate_t; the output is bounded by the code point */
        uint32_t wc=(uint32_t)x[1]; size_t n=wc<0x80?1:wc<0x800?2:wc<0x10000?3:wc<0x110000?4:0; void *out=NULL;
        if (x[2] && !bb_access(e,x[2],8,BB_R|BB_W)) return false;
        if (x[0] && n && !bb_host_data_alias(e,x[0],n,&out)) return false;
        if (x[0] && !n) out=(void *)(uintptr_t)x[0];   /* the shim does not write for an invalid code point */
        r=((size_t (*)(char *,wchar_t,void *))fn)(out,(wchar_t)wc,NULL); break; }
    case LRT_SYNC: {                    /* pthread mutex/cond/rwlock/attr objects through Husk's shim, on the writable alias */
        void *p[3]={0}; unsigned sz[3]={m->arg&255,(m->arg>>8)&255,(m->arg>>16)&255};
        for (int i=0;i<3;i++) {
            if (!sz[i]) { p[i]=(void *)(uintptr_t)x[i]; continue; }
            bool opt=(i==1 && (m->arg&RT_OPT1)) || (i==2 && (m->arg&RT_OPT2));
            if (!x[i] && opt) continue;
            if (!bb_host_data_alias(e,x[i],sz[i],&p[i])) return false;
        }
        r=(uint32_t)((int (*)(void *,void *,void *))fn)(p[0],p[1],p[2]); break; }
    case LRT_INT:                       /* integer-only process/system queries */
        r=(uint64_t)((long (*)(long,long,long))fn)((long)x[0],(long)x[1],(long)x[2]); break;
    case LRT_NANOSLEEP: {               /* (const struct timespec *req, struct timespec *rem): 16 bytes each */
        if (!bb_access(e,x[0],16,BB_R) || (x[1] && !bb_host_data_alias(e,x[1],16,&alias))) return false;
        r=(uint32_t)((int (*)(const void *,void *))fn)((const void *)(uintptr_t)x[0],alias); break; }
    case LRT_SIGACTION: {               /* (sig, const struct sigaction *act, struct sigaction *old) */
        int sig=(int)x[0]; uint8_t act[GUEST_SIGACTION]; void *oldp=NULL;
        if (sig<1 || sig>64 || sig==9 || sig==19) { tl_set_guest_errno(22); r=(uint64_t)-1; break; }   /* SIGKILL/SIGSTOP: EINVAL */
        if ((x[1] && !bb_read(e,x[1],act,GUEST_SIGACTION)) || (x[2] && !bb_host_data_alias(e,x[2],GUEST_SIGACTION,&oldp))) return false;
        pthread_mutex_lock(&rt_sig_lock);
        if (oldp) memcpy(oldp,rt_sigact[sig],GUEST_SIGACTION);
        if (x[1]) memcpy(rt_sigact[sig],act,GUEST_SIGACTION);
        pthread_mutex_unlock(&rt_sig_lock);
        r=0; break; }
    case LRT_SIGNAL: {                  /* signal(sig, handler) -> previous handler */
        int sig=(int)x[0]; uint64_t prev;
        if (sig<1 || sig>64 || sig==9 || sig==19) { tl_set_guest_errno(22); r=(uint64_t)-1; break; }   /* SIG_ERR */
        pthread_mutex_lock(&rt_sig_lock);
        memcpy(&prev,rt_sigact[sig]+8,8); memset(rt_sigact[sig],0,GUEST_SIGACTION); memcpy(rt_sigact[sig]+8,&x[1],8);
        pthread_mutex_unlock(&rt_sig_lock);
        r=prev; break; }
    case LRT_STRERROR: {                /* a guest copy per error number: the text is immutable */
        uint32_t en=(uint32_t)x[0], slot=en<255?en:255;
        pthread_mutex_lock(&rt_err_lock); r=slot<255?rt_err_copy[slot]:0; pthread_mutex_unlock(&rt_err_lock);
        if (r) break;
        const char *t=((const char *(*)(int))fn)((int)x[0]); size_t n=t?strnlen(t,1024):0;
        r=bb_heap_malloc(e,n+1); if (!r || !bb_write(e,r,t?t:"",n) || !bb_write(e,r+n,"",1)) return false;
        if (slot<255) { pthread_mutex_lock(&rt_err_lock); if (!rt_err_copy[slot]) rt_err_copy[slot]=r; pthread_mutex_unlock(&rt_err_lock); }
        break; }
    case LRT_STRERROR_R: {              /* POSIX: (errnum, buf, len) -> int */
        size_t len=(size_t)x[2]; char tmp[1024];
        if (len>(1u<<20) || (len && !bb_host_data_alias(e,x[1],len,&alias))) return false;
        int rc=((int (*)(int,char *,size_t))fn)((int)x[0],tmp,sizeof(tmp));
        if (len) { size_t n=strnlen(tmp,sizeof(tmp)); if (n>=len) { n=len-1; if (!rc) rc=34; } memcpy(alias,tmp,n); ((char *)alias)[n]=0; }
        r=(uint32_t)rc; break; }
    case LRT_KEY_CREATE: {              /* (int *key, guest destructor) */
        if (!bb_host_data_alias(e,x[0],4,&alias) || (x[1] && !bb_access(e,x[1],4,BB_X))) return false;
        pthread_mutex_lock(&rt_key_lock); int32_t k=-1;
        for (int i=0;i<OOP_KEYS;i++) if (!rt_keys[i].used) { k=i; break; }
        if (k>=0 && pthread_key_create(&rt_keys[k].key,NULL)==0) { rt_keys[k].used=true; rt_keys[k].destructor=x[1]; } else k=-1;
        pthread_mutex_unlock(&rt_key_lock);
        if (k<0) { r=11; break; }   /* EAGAIN */
        memcpy(alias,&k,4); r=0; break; }
    case LRT_KEY_DELETE: {
        pthread_key_t hk; if (!rt_key((uint32_t)x[0],&hk)) { r=22; break; }
        pthread_mutex_lock(&rt_key_lock); pthread_key_delete(hk); rt_keys[(uint32_t)x[0]].used=false; pthread_mutex_unlock(&rt_key_lock);
        r=0; break; }
    case LRT_GETSPECIFIC: { pthread_key_t hk; r=rt_key((uint32_t)x[0],&hk)?(uintptr_t)pthread_getspecific(hk):0; break; }
    case LRT_SETSPECIFIC: { pthread_key_t hk; r=rt_key((uint32_t)x[0],&hk)?(uint32_t)pthread_setspecific(hk,(void *)(uintptr_t)x[1]):22; break; }
    default: return false;
    }
    *result=r; ++m->calls; m->owner->last=m->name; return true;
}
int oop_imports_register_runtime(oop_imports *b) {
    if (!b) return -1;
    static const struct { const char *name; unsigned shape, arg; } table[]={
        {"malloc",LRT_MALLOC},{"free",LRT_FREE},{"calloc",LRT_CALLOC},{"realloc",LRT_REALLOC},
        {"pthread_mutex_lock",LRT_SYNC40},{"pthread_mutex_unlock",LRT_SYNC40},{"pthread_mutex_destroy",LRT_SYNC40},
        {"pthread_cond_broadcast",LRT_SYNC48},{"pthread_cond_destroy",LRT_SYNC48},
        {"syscall",LRT_GETTID},{"arc4random",LRT_RANDOM},{"sigfillset",LRT_SIGFILL},{"sigdelset",LRT_SIGDEL},
        {"getenv",LRT_GETENV},{"strtoul",LRT_STRTOUL},{"wcrtomb",LRT_WCRTOMB},
        {"pthread_mutex_init",LRT_SYNC,RT_SYNC(40,8,0,RT_OPT1)},{"pthread_mutex_trylock",LRT_SYNC,RT_SYNC(40,0,0,0)},
        {"pthread_mutexattr_init",LRT_SYNC,RT_SYNC(8,0,0,0)},{"pthread_mutexattr_destroy",LRT_SYNC,RT_SYNC(8,0,0,0)},
        {"pthread_mutexattr_settype",LRT_SYNC,RT_SYNC(8,0,0,0)},
        {"pthread_cond_init",LRT_SYNC,RT_SYNC(48,8,0,RT_OPT1)},{"pthread_cond_signal",LRT_SYNC,RT_SYNC(48,0,0,0)},
        {"pthread_cond_wait",LRT_SYNC,RT_SYNC(48,40,0,0)},{"pthread_cond_timedwait",LRT_SYNC,RT_SYNC(48,40,16,0)},
        {"pthread_rwlock_init",LRT_SYNC,RT_SYNC(56,8,0,RT_OPT1)},{"pthread_rwlock_destroy",LRT_SYNC,RT_SYNC(56,0,0,0)},
        {"pthread_rwlock_rdlock",LRT_SYNC,RT_SYNC(56,0,0,0)},{"pthread_rwlock_wrlock",LRT_SYNC,RT_SYNC(56,0,0,0)},
        {"pthread_rwlock_unlock",LRT_SYNC,RT_SYNC(56,0,0,0)},
        {"strerror",LRT_STRERROR},{"strerror_r",LRT_STRERROR_R},
        {"getpid",LRT_INT},{"getuid",LRT_INT},{"geteuid",LRT_INT},{"getgid",LRT_INT},{"getegid",LRT_INT},{"sysconf",LRT_INT},
        {"getpriority",LRT_INT},{"setpriority",LRT_INT},{"alarm",LRT_INT},{"sched_yield",LRT_INT},{"usleep",LRT_INT},
        {"getauxval",LRT_INT},{"clock",LRT_INT},{"nanosleep",LRT_NANOSLEEP},
        {"sigaction",LRT_SIGACTION},{"signal",LRT_SIGNAL},
        {"pthread_key_create",LRT_KEY_CREATE},{"pthread_key_delete",LRT_KEY_DELETE},
        {"pthread_getspecific",LRT_GETSPECIFIC},{"pthread_setspecific",LRT_SETSPECIFIC},
    };
    int registered=0;
    for (size_t i=0;i<sizeof(table)/sizeof(table[0]);i++) {
        void *fn=tl_bionic_find(table[i].name);
        if (!fn) continue;
        bool dup=false; for (size_t k=0;k<b->n;k++) if (b->v[k].token==(uintptr_t)fn) { dup=true; break; }
        if (dup) continue;
        if (b->n>=OOP_IMPORTS_MAX) return -1;
        oop_import *slot=&b->v[b->n];
        *slot=(oop_import){.owner=b,.token=(uintptr_t)fn,.name=table[i].name,.fn=fn,.shape=table[i].shape,.arg=table[i].arg};
        if (!oop_domain_register_host(b->domain,(uintptr_t)fn,imp_runtime,slot)) return -1;
        ++b->n; ++registered;
    }
    return registered;
}
/* ============================================================ sockets
 * Husk's bionic socket layer (husk-tl-bionic-net.c / -io.c) already speaks
 * Android: Linux domain/type/flag values, Linux sockaddr layouts, bionic
 * struct addrinfo, the shared fd table. The bridge only moves guest buffers
 * across: inputs at their guest address over exactly the length the call
 * reads, outputs through the writable alias over exactly the length it may
 * write, value-result lengths read and written back in guest memory. Nothing
 * here inspects or changes the data sent or received. */
enum { LN_INT3, LN_SOCKETPAIR, LN_SOCKADDR_IN, LN_SOCKADDR_OUT, LN_SETSOCKOPT, LN_GETSOCKOPT, LN_SEND, LN_RECV, LN_SENDTO,
       LN_SENDTO_CHK, LN_RECVFROM, LN_POLL, LN_SELECT, LN_FCNTL, LN_IOCTL, LN_GETADDRINFO, LN_FREEADDRINFO, LN_GAI_STRERROR,
       LN_INET_NTOP, LN_INET_PTON, LN_GETHOSTNAME, LN_NAMETOINDEX, LN_GETNAMEINFO };
#define BIONIC_ADDRINFO 48u
#define BIONIC_ADDRINFO_DATA 128u
static pthread_mutex_t ln_lock=PTHREAD_MUTEX_INITIALIZER;
static uint64_t ln_lists[64]; static size_t ln_nlists;
static uint64_t ln_gai_text[32];
/* A value-result socklen_t: read the guest's capacity, alias the buffer for it. */
static bool ln_out(bb_engine *e, uint64_t buf, uint64_t lenp, void **bufa, void **lena, uint32_t cap) {
    *bufa=NULL; *lena=NULL;
    if (!lenp) return !buf;
    uint32_t n; if (!bb_read(e,lenp,&n,4) || n>cap || !bb_host_data_alias(e,lenp,4,lena)) return false;
    if (buf && n && !bb_host_data_alias(e,buf,n,bufa)) return false;
    if (buf && !n) *bufa=(void *)(uintptr_t)buf;   /* zero capacity: nothing is written */
    return true;
}
static bool imp_net(const bb_state *s, uint64_t *result, void *opaque) {
    oop_import *m=opaque; bb_engine *e=m->owner->engine; void *fn=m->fn; const uint64_t *x=s->x; void *a=NULL,*b=NULL; size_t l1;
    uint64_t r=0;
    switch (m->shape) {
    case LN_INT3:                       /* socket, listen, shutdown: integers only */
        r=(uint32_t)((int (*)(int,int,int))fn)((int)x[0],(int)x[1],(int)x[2]); break;
    case LN_SOCKETPAIR:
        if (!bb_host_data_alias(e,x[3],8,&a)) return false;
        r=(uint32_t)((int (*)(int,int,int,void *))fn)((int)x[0],(int)x[1],(int)x[2],a); break;
    case LN_SOCKADDR_IN:                /* bind/connect(fd, const sockaddr *, len) */
        if ((uint32_t)x[2]>256 || (x[2] && !bb_access(e,x[1],(size_t)(uint32_t)x[2],BB_R))) return false;
        r=(uint32_t)((int (*)(int,const void *,uint32_t))fn)((int)x[0],(const void *)(uintptr_t)x[1],(uint32_t)x[2]); break;
    case LN_SOCKADDR_OUT:               /* accept/getsockname/getpeername(fd, sockaddr *, socklen_t *) */
        if (!ln_out(e,x[1],x[2],&a,&b,256)) return false;
        r=(uint32_t)((int (*)(int,void *,void *))fn)((int)x[0],a,b); break;
    case LN_SETSOCKOPT:                 /* (fd, level, name, const void *, len) */
        if ((uint32_t)x[4]>1024 || (x[4] && !bb_access(e,x[3],(size_t)(uint32_t)x[4],BB_R))) return false;
        r=(uint32_t)((int (*)(int,int,int,const void *,uint32_t))fn)((int)x[0],(int)x[1],(int)x[2],(const void *)(uintptr_t)x[3],(uint32_t)x[4]); break;
    case LN_GETSOCKOPT:                 /* (fd, level, name, void *, socklen_t *) */
        if (!ln_out(e,x[3],x[4],&a,&b,1024)) return false;
        r=(uint32_t)((int (*)(int,int,int,void *,void *))fn)((int)x[0],(int)x[1],(int)x[2],a,b); break;
    case LN_SEND:                       /* (fd, buf, n, flags) */
        if (x[2]>(UINT64_C(1)<<31) || (x[2] && !bb_access(e,x[1],(size_t)x[2],BB_R))) return false;
        r=(uint64_t)((long (*)(int,const void *,size_t,int))fn)((int)x[0],(const void *)(uintptr_t)x[1],(size_t)x[2],(int)x[3]); break;
    case LN_RECV:
        if (x[2]>(UINT64_C(1)<<31) || (x[2] && !bb_host_data_alias(e,x[1],(size_t)x[2],&a))) return false;
        r=(uint64_t)((long (*)(int,void *,size_t,int))fn)((int)x[0],a,(size_t)x[2],(int)x[3]); break;
    case LN_SENDTO: case LN_SENDTO_CHK: {   /* (fd, buf, n, [buflen,] flags, addr, alen) */
        int o=m->shape==LN_SENDTO_CHK; uint64_t n=x[2], flags=x[3+o], addr=x[4+o], alen=(uint32_t)x[5+o];
        if (o && n>x[3]) return false;
        if (n>(UINT64_C(1)<<31) || (n && !bb_access(e,x[1],(size_t)n,BB_R)) || alen>256 || (alen && !bb_access(e,addr,(size_t)alen,BB_R))) return false;
        r=(uint64_t)((long (*)(int,const void *,size_t,int,const void *,uint32_t))tl_bionic_find("sendto"))((int)x[0],(const void *)(uintptr_t)x[1],(size_t)n,(int)flags,(const void *)(uintptr_t)addr,(uint32_t)alen);
        break; }
    case LN_RECVFROM: {                 /* (fd, buf, n, flags, addr, socklen_t *) */
        void *c=NULL;
        if (x[2]>(UINT64_C(1)<<31) || (x[2] && !bb_host_data_alias(e,x[1],(size_t)x[2],&a)) || !ln_out(e,x[4],x[5],&b,&c,256)) return false;
        r=(uint64_t)((long (*)(int,void *,size_t,int,void *,void *))fn)((int)x[0],a,(size_t)x[2],(int)x[3],b,c); break; }
    case LN_POLL:                       /* (struct pollfd *, nfds, timeout): 8-byte entries, same on both sides */
        if (x[1]>4096 || (x[1] && !bb_host_data_alias(e,x[0],(size_t)x[1]*8,&a))) return false;
        r=(uint32_t)((int (*)(void *,unsigned long,int))fn)(a,(unsigned long)x[1],(int)x[2]); break;
    case LN_SELECT: {                   /* (n, fd_set *r, *w, *e, struct timeval *): Linux fd_set is 128 bytes */
        void *sets[3]={0}, *tv=NULL;
        if ((int)x[0]<0 || (int)x[0]>1024) return false;
        for (int i=0;i<3;i++) if (x[1+i] && !bb_host_data_alias(e,x[1+i],128,&sets[i])) return false;
        if (x[4] && !bb_host_data_alias(e,x[4],16,&tv)) return false;
        r=(uint32_t)((int (*)(int,void *,void *,void *,void *))fn)((int)x[0],sets[0],sets[1],sets[2],tv); break; }
    case LN_FCNTL: {                    /* integer-argument commands only; lock structures are refused */
        int cmd=(int)x[1];
        if (cmd!=0 && cmd!=1 && cmd!=2 && cmd!=3 && cmd!=4 && cmd!=1030) return gl_refuse(m,"fcntl command with a pointer argument");
        r=(uint32_t)((int (*)(int,int,long))fn)((int)x[0],cmd,(long)x[2]); break; }
    case LN_IOCTL: {                    /* FIONBIO (int in), FIONREAD (int out) */
        unsigned long req=(unsigned long)(uint32_t)x[1];
        if (req!=0x5421 && req!=0x541B) return gl_refuse(m,"ioctl request not bridged");
        if (!bb_host_data_alias(e,x[2],4,&a)) return false;
        r=(uint32_t)((int (*)(int,unsigned long,void *))fn)((int)x[0],req,a); break; }
    case LN_GETADDRINFO: {              /* (node, service, hints, struct addrinfo **res): the list is copied into the guest heap */
        uint64_t out_guest=0; void *resa; struct ln_ai { int f,fam,st,pr; uint32_t alen; uint64_t canon, addr, next; } *h=NULL;
        if ((x[0] && !lc_str(e,x[0],&l1)) || (x[1] && !lc_str(e,x[1],&l1)) || (x[2] && !bb_access(e,x[2],BIONIC_ADDRINFO,BB_R)) ||
            !bb_host_data_alias(e,x[3],8,&resa)) return false;
        int rc=((int (*)(const char *,const char *,const void *,void **))fn)((const char *)(uintptr_t)x[0],(const char *)(uintptr_t)x[1],
                                                                            (const void *)(uintptr_t)x[2],(void **)&h);
        if (!rc) {
            uint64_t *link=&out_guest, prev=0; bool ok=true;
            for (struct ln_ai *p=h;p && ok;p=(struct ln_ai *)(uintptr_t)p->next) {
                size_t canon=p->canon?strnlen((const char *)(uintptr_t)p->canon,1024)+1:0, total=BIONIC_ADDRINFO+BIONIC_ADDRINFO_DATA+canon;
                uint64_t g=bb_heap_malloc(e,total); uint8_t node[BIONIC_ADDRINFO+BIONIC_ADDRINFO_DATA];
                if (!g || p->alen>BIONIC_ADDRINFO_DATA) { if (g) bb_heap_free(e,g); ok=false; break; }
                struct ln_ai c=*p; c.addr=g+BIONIC_ADDRINFO; c.canon=canon?g+BIONIC_ADDRINFO+BIONIC_ADDRINFO_DATA:0; c.next=0;
                memset(node,0,sizeof(node)); memcpy(node,&c,sizeof(c)); memcpy(node+BIONIC_ADDRINFO,(const void *)(uintptr_t)p->addr,p->alen);
                ok=bb_write(e,g,node,sizeof(node)) && (!canon || bb_write(e,g+BIONIC_ADDRINFO+BIONIC_ADDRINFO_DATA,(const void *)(uintptr_t)p->canon,canon));
                if (prev) ok=ok && bb_write(e,prev+offsetof(struct ln_ai,next),&g,8); else *link=g;
                prev=g;
            }
            ((void (*)(void *))tl_bionic_find("freeaddrinfo"))(h);
            if (!ok) { for (uint64_t g=out_guest,n;g;g=n) { if (!bb_read(e,g+offsetof(struct ln_ai,next),&n,8)) n=0; bb_heap_free(e,g); } return false; }
            pthread_mutex_lock(&ln_lock); bool room=ln_nlists<64; if (room) ln_lists[ln_nlists++]=out_guest; pthread_mutex_unlock(&ln_lock);
            if (!room) return false;
            memcpy(resa,&out_guest,8);
        }
        r=(uint32_t)rc; break; }
    case LN_FREEADDRINFO: {             /* only a list this bridge made */
        bool known=false;
        pthread_mutex_lock(&ln_lock);
        for (size_t i=0;i<ln_nlists;i++) if (ln_lists[i]==x[0]) { ln_lists[i]=ln_lists[--ln_nlists]; known=true; break; }
        pthread_mutex_unlock(&ln_lock);
        if (!known) return x[0]==0;
        for (uint64_t g=x[0],n;g;g=n) { if (!bb_read(e,g+40,&n,8)) return false; if (!bb_heap_free(e,g)) return false; }
        break; }
    case LN_GAI_STRERROR: {             /* a guest copy per code */
        int code=(int)x[0]; unsigned slot=(unsigned)(code<0?-code:code)%32;
        pthread_mutex_lock(&ln_lock); r=ln_gai_text[slot]; pthread_mutex_unlock(&ln_lock);
        const char *t=((const char *(*)(int))fn)(code); size_t n=t?strnlen(t,256):0;
        if (r) { char cur[260]={0}; if (!bb_read(e,r,cur,n+1) || memcmp(cur,t?t:"",n) || cur[n]) r=0; }
        if (!r) { r=bb_heap_malloc(e,n+1); if (!r || !bb_write(e,r,t?t:"",n) || !bb_write(e,r+n,"",1)) return false;
                  pthread_mutex_lock(&ln_lock); ln_gai_text[slot]=r; pthread_mutex_unlock(&ln_lock); }
        break; }
    case LN_INET_NTOP: {                /* (af, src, dst, size) -> dst */
        size_t in=(int)x[0]==10?16:4;
        if ((uint32_t)x[3]>256 || !bb_access(e,x[1],in,BB_R) || ((uint32_t)x[3] && !bb_host_data_alias(e,x[2],(uint32_t)x[3],&a))) return false;
        r=((const char *(*)(int,const void *,char *,uint32_t))fn)((int)x[0],(const void *)(uintptr_t)x[1],a,(uint32_t)x[3])?x[2]:0; break; }
    case LN_INET_PTON: {                /* (af, src string, dst) */
        size_t out=(int)x[0]==10?16:4;
        if (!lc_str(e,x[1],&l1) || !bb_host_data_alias(e,x[2],out,&a)) return false;
        r=(uint32_t)((int (*)(int,const char *,void *))fn)((int)x[0],(const char *)(uintptr_t)x[1],a); break; }
    case LN_GETHOSTNAME:
        if (x[1]>1024 || (x[1] && !bb_host_data_alias(e,x[0],(size_t)x[1],&a))) return false;
        r=(uint32_t)((int (*)(char *,size_t))fn)(a,(size_t)x[1]); break;
    case LN_NAMETOINDEX:
        if (!lc_str(e,x[0],&l1)) return false;
        r=(uint32_t)((unsigned (*)(const char *))fn)((const char *)(uintptr_t)x[0]); break;
    case LN_GETNAMEINFO: {              /* (sa, salen, host, hostlen, serv, servlen, flags) */
        void *ho=NULL,*se=NULL;
        if ((uint32_t)x[1]>256 || !bb_access(e,x[0],(uint32_t)x[1],BB_R) || (uint32_t)x[3]>1025 || (uint32_t)x[5]>256 ||
            (x[2] && x[3] && !bb_host_data_alias(e,x[2],(uint32_t)x[3],&ho)) || (x[4] && x[5] && !bb_host_data_alias(e,x[4],(uint32_t)x[5],&se))) return false;
        r=(uint32_t)((int (*)(const void *,uint32_t,char *,uint32_t,char *,uint32_t,int))fn)((const void *)(uintptr_t)x[0],(uint32_t)x[1],ho,(uint32_t)x[3],se,(uint32_t)x[5],(int)x[6]);
        break; }
    default: return false;
    }
    *result=r; ++m->calls; m->owner->last=m->name; return true;
}
int oop_imports_register_net(oop_imports *b) {
    if (!b) return -1;
    static const struct { const char *name; unsigned shape; } table[]={
        {"socket",LN_INT3},{"listen",LN_INT3},{"shutdown",LN_INT3},{"socketpair",LN_SOCKETPAIR},
        {"bind",LN_SOCKADDR_IN},{"connect",LN_SOCKADDR_IN},{"accept",LN_SOCKADDR_OUT},{"getsockname",LN_SOCKADDR_OUT},{"getpeername",LN_SOCKADDR_OUT},
        {"setsockopt",LN_SETSOCKOPT},{"getsockopt",LN_GETSOCKOPT},{"send",LN_SEND},{"recv",LN_RECV},{"sendto",LN_SENDTO},
        {"__sendto_chk",LN_SENDTO_CHK},{"recvfrom",LN_RECVFROM},{"poll",LN_POLL},{"select",LN_SELECT},{"fcntl",LN_FCNTL},{"ioctl",LN_IOCTL},
        {"getaddrinfo",LN_GETADDRINFO},{"freeaddrinfo",LN_FREEADDRINFO},{"gai_strerror",LN_GAI_STRERROR},
        {"inet_ntop",LN_INET_NTOP},{"inet_pton",LN_INET_PTON},{"gethostname",LN_GETHOSTNAME},{"if_nametoindex",LN_NAMETOINDEX},
        {"getnameinfo",LN_GETNAMEINFO},
    };
    int registered=0;
    for (size_t i=0;i<sizeof(table)/sizeof(table[0]);i++) {
        void *fn=tl_bionic_find(table[i].name);
        if (!fn) continue;
        bool dup=false; for (size_t k=0;k<b->n;k++) if (b->v[k].token==(uintptr_t)fn) { dup=true; break; }
        if (dup) continue;
        if (b->n>=OOP_IMPORTS_MAX) return -1;
        oop_import *slot=&b->v[b->n];
        *slot=(oop_import){.owner=b,.token=(uintptr_t)fn,.name=table[i].name,.fn=fn,.shape=table[i].shape};
        if (!oop_domain_register_host(b->domain,(uintptr_t)fn,imp_net,slot)) return -1;
        ++b->n; ++registered;
    }
    return registered;
}
int oop_imports_register_setjmp(oop_imports *b) {
    if (!b) return -1;
    uint64_t f[4]; const char *n[4]={"setjmp","sigsetjmp","longjmp","siglongjmp"}; int c=0;
    for (int i=0;i<4;i++) { f[i]=(uintptr_t)tl_bionic_find(n[i]); c+=f[i]!=0; }
    uint64_t once=(uintptr_t)tl_bionic_find("pthread_once");
    if (once && !oop_domain_register_once(b->domain,once)) return -1;
    if (!oop_domain_register_sort(b->domain,(uintptr_t)tl_bionic_find("qsort"),(uintptr_t)tl_bionic_find("bsearch"))) return -1;
    return oop_domain_register_setjmp(b->domain,f[0],f[1],f[2],f[3]) ? c+(once!=0) : -1;
}
int oop_imports_bind_data(oop_imports *b, unsigned *left_host_bound) {
    if (!b) return -1;
#ifndef HUSK_OOP_IOS_DIAG
    if (left_host_bound) *left_host_bound=0;
    return 0;   /* the loader records data imports only in the out-of-place diagnostic build */
#else
    const tl_ld_oop_data_import *d; size_t n=tl_ld_oop_data_imports(&d); int bound=0; unsigned left=0;
    /* name and ABI size (an undefined symbol's st_size is 0) */
    static const struct { const char *name; size_t size; } copyable[]={{"__stack_chk_guard",8}};   /* the stack protector's guard: fixed for the process */
    for (size_t i=0;i<n;i++) {
        size_t size=0;
        for (size_t k=0;k<sizeof(copyable)/sizeof(copyable[0]);k++) if (!strcmp(d[i].name,copyable[k].name)) size=copyable[k].size;
        if (!size) { ++left; continue; }
        uint64_t g=bb_heap_malloc(b->engine,size), slot=g+d[i].addend;
        if (!g || !bb_write(b->engine,g,(const void *)(uintptr_t)d[i].host,size) || !bb_write(b->engine,d[i].slot,&slot,8)) return -1;
        ++bound;
    }
    if (left_host_bound) *left_host_bound=left;
    return bound;
#endif
}
unsigned oop_imports_calls(const oop_imports *b) {
    unsigned t=0; if (b) for (size_t i=0;i<b->n;i++) t+=b->v[i].calls; return t;
}
const char *oop_imports_last(const oop_imports *b) { return b?b->last:NULL; }
size_t oop_imports_count(const oop_imports *b) { return b?b->n:0; }
#endif
