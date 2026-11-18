/* SPDX-License-Identifier: GPL-2.0-or-later */
#if defined(HUSK_OOP_IOS_DIAG) || defined(HUSK_OOP_DOMAIN_TEST)
#include "husk-oop-domain.h"
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>

#define ENTRY_LIMIT 65536
#define HOST_LIMIT 8192
#define RETURN_PC UINT64_C(0xfffffffffffffff0)
typedef struct { uint64_t token; oop_host_callback callback; void *opaque; } host_entry;
/* Each host thread that enters the guest has its own call-stack bookkeeping:
 * nesting depth and the suspended frame's state/SP for re-entry below it. The
 * guest register file is the caller's own bb_state, so no register state lives
 * here. Shared across threads are only the (immutable-after-setup, else
 * reg_lock-guarded) entry and host tables and the one engine and heap. */
typedef struct oop_thread {
    size_t depth;
    const bb_state *host_state;
    bb_state *host_result;       /* the transition being served, for an FP result */
    uint64_t host_stack;
    uint64_t tls;                /* attached guest TPIDR_EL0, 0 when not attached */
    struct oop_domain *owner;    /* for the attached-thread count at thread exit */
} oop_thread;
struct oop_domain {
    bb_engine *engine;
    uint64_t *entries;
    size_t count, capacity;
    host_entry *hosts;
    size_t host_count, host_capacity;
    pthread_mutex_t reg_lock;    /* entries/hosts arrays: lazy runtime registration vs. concurrent lookup */
    pthread_key_t tkey;          /* oop_thread per entering thread */
    bool threaded;
    _Atomic unsigned attached;   /* host threads with a declared guest TLS */
    int *(*host_errno)(void);    /* Husk's per-host-thread guest errno, or NULL */
    uint64_t errno_offset;       /* the guest thread's errno word: TPIDR_EL0 + offset */
#ifdef BB_TESTING
    bool reference;
#endif
};
static oop_thread *thread_ctx(oop_domain *d) {
    oop_thread *t=pthread_getspecific(d->tkey);
    if (!t) { t=calloc(1,sizeof(*t)); if (t) t->owner=d;
        if (t && pthread_setspecific(d->tkey,t)) { free(t); t=NULL; } }
    return t;
}
/* Thread exit: the record goes; an attached thread stops counting. */
static void thread_ctx_free(void *p) {
    oop_thread *t=p;
    if (t && t->tls && t->owner) atomic_fetch_sub(&t->owner->attached,1);
    free(t);
}
bool oop_domain_thread_attach(oop_domain *d, uint64_t tls) {
    if (!d || !tls || (tls&7)) return false;   /* identity only: TLS memory is checked where it is used */
    oop_thread *t=thread_ctx(d); if (!t) return false;
    if (t->tls) return t->tls==tls;
    t->tls=tls; atomic_fetch_add(&d->attached,1); return true;
}
void oop_domain_thread_detach(oop_domain *d) {
    oop_thread *t=d?pthread_getspecific(d->tkey):NULL;
    if (!t || !t->tls || t->depth) return;   /* never while this thread is inside the guest */
    t->tls=0; atomic_fetch_sub(&d->attached,1);
}
bool oop_domain_thread_owns(oop_domain *d, uint64_t tls) {
    oop_thread *t=d?pthread_getspecific(d->tkey):NULL;
    return t && tls && t->tls==tls;
}
unsigned oop_domain_thread_count(oop_domain *d) { return d?atomic_load(&d->attached):0; }
static bool host_transition(bb_state *s, void *opaque) {
    oop_domain *d=opaque; uint64_t result=0;
    if ((s->sp&15) || s->sp<16 || !bb_access(d->engine,s->sp-16,16,BB_R|BB_W)) return false;
    oop_thread *t=thread_ctx(d); if (!t) return false;
    if (d->threaded) pthread_mutex_lock(&d->reg_lock);
    size_t lo=0,hi=d->host_count;
    while (lo<hi) { size_t m=lo+(hi-lo)/2; if (d->hosts[m].token<s->pc) lo=m+1; else hi=m; }
    bool found=lo<d->host_count && d->hosts[lo].token==s->pc;
    host_entry host=found?d->hosts[lo]:(host_entry){0};
    if (d->threaded) pthread_mutex_unlock(&d->reg_lock);
    if (!found) return false;
    const bb_state *previous_state=t->host_state; bb_state *previous_result=t->host_result; uint64_t previous_stack=t->host_stack;
    t->host_state=s; t->host_result=s; t->host_stack=s->sp;
    /* errno coherence: the host call sees the guest thread's errno and the
     * guest sees whatever the host call left there. */
    int *herr=d->host_errno?d->host_errno():NULL; uint64_t eslot=s->tpidr_el0+d->errno_offset; int32_t gerr;
    if (herr && bb_read(d->engine,eslot,&gerr,4)) *herr=gerr; else herr=NULL;
    bool ok=host.callback(s,&result,host.opaque);
    if (herr) { gerr=*herr; if (!bb_write(d->engine,eslot,&gerr,4)) ok=false; }
    t->host_state=previous_state; t->host_result=previous_result; t->host_stack=previous_stack;
    if (!ok) return false;
    s->x[0]=result;
    return true;
}
bool oop_domain_set_errno(oop_domain *d, int *(*host_errno)(void), uint64_t tls_offset) {
    if (!d || !host_errno || (tls_offset&3) || tls_offset<0x40 || tls_offset>0xffc || d->threaded) return false;
    d->errno_offset=tls_offset; d->host_errno=host_errno; return true;
}
/* ------------------------------------------------ setjmp / longjmp
 * On guest state: the jmp_buf (guest memory, bionic's 256 bytes; 184 used)
 * holds a cookie, the domain call depth, SP, x19-x30 and d8-d15. longjmp is
 * honoured only within the same guest call (same depth): unwinding through a
 * host frame is refused, never performed. Signal masks are not saved. */
#define OOP_JMP_COOKIE UINT64_C(0x4f4f504a4d504255)
#define OOP_JMP_WORDS 23
static bool oop_setjmp_gate(const bb_state *s, uint64_t *result, void *opaque) {
    oop_domain *d=opaque; oop_thread *t=pthread_getspecific(d->tkey); uint64_t w[OOP_JMP_WORDS]; void *out;
    if (!t || !bb_host_data_alias(d->engine,s->x[0],sizeof(w),&out)) return false;
    w[0]=OOP_JMP_COOKIE; w[1]=t->depth; w[2]=s->sp;
    for (int i=0;i<12;i++) w[3+i]=s->x[19+i];
    for (int i=0;i<8;i++) w[15+i]=s->v[8+i][0];
    memcpy(out,w,sizeof(w)); *result=0; return true;
}
static bool oop_longjmp_gate(const bb_state *s, uint64_t *result, void *opaque) {
    oop_domain *d=opaque; oop_thread *t=pthread_getspecific(d->tkey); uint64_t w[OOP_JMP_WORDS];
    if (!t || !t->host_result || !bb_read(d->engine,s->x[0],w,sizeof(w)) || w[0]!=OOP_JMP_COOKIE || w[1]!=t->depth) return false;
    if ((w[2]&15) || w[2]<s->sp) return false;   /* only to an enclosing (higher) frame of this guest call */
    bb_state *r=t->host_result;
    r->sp=w[2];
    for (int i=0;i<12;i++) r->x[19+i]=w[3+i];
    for (int i=0;i<8;i++) { r->v[8+i][0]=w[15+i]; r->v[8+i][1]=0; }
    r->pc=w[14];                                  /* setjmp's return address (saved x30) */
    *result=(uint32_t)s->x[1]?(uint32_t)s->x[1]:1; return true;
}
/* ------------------------------------------------------- pthread_once
 * bionic's pthread_once_t is an int: 0 not started, 1 underway, 2 complete.
 * The first caller runs the guest init routine as a nested guest call on its
 * own thread; others wait (no engine lock held) until it completes. */
static pthread_mutex_t oop_once_lock=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t oop_once_cv=PTHREAD_COND_INITIALIZER;
static bool oop_once_gate(const bb_state *s, uint64_t *result, void *opaque) {
    oop_domain *d=opaque; uint64_t ctl=s->x[0], fn=s->x[1]; int32_t st; uint64_t sp;
    if (!bb_access(d->engine,ctl,4,BB_R|BB_W)) return false;
    pthread_mutex_lock(&oop_once_lock);
    for (;;) {
        if (!bb_read(d->engine,ctl,&st,4)) { pthread_mutex_unlock(&oop_once_lock); return false; }
        if (st==2) { pthread_mutex_unlock(&oop_once_lock); *result=0; return true; }
        if (st==0) break;
        pthread_cond_wait(&oop_once_cv,&oop_once_lock);
    }
    st=1; bool ok=bb_write(d->engine,ctl,&st,4);
    pthread_mutex_unlock(&oop_once_lock);
    if (!ok || !oop_domain_reentry_stack(d,&sp) || !oop_domain_register_entry(d,fn)) {
        void tl_log_line(const char *, ...); tl_log_line("oop: pthread_once %#llx: no nested guest frame", (unsigned long long)fn); return false; }
    bb_state n={0}; bb_result gr; n.sp=sp; n.tpidr_el0=s->tpidr_el0;
    oop_gate_result g=oop_domain_call(d,fn,OOP_ABI_INTEGER_0_TO_8,&n,2000000000u,&gr);
    if (g!=OOP_GATE_OK) { void tl_log_line(const char *, ...);
#ifdef HUSK_OOP_IOS_DIAG
        const char *tl_bionic_name_of(const void *); const char *hn=tl_bionic_name_of((void *)(uintptr_t)n.pc);
#else
        const char *hn=NULL;
#endif
        tl_log_line("oop: pthread_once routine %#llx stopped: gate=%d guest=%s pc=%#llx%s%s lr=%#llx", (unsigned long long)fn, g, bb_result_name(gr),
                    (unsigned long long)n.pc, hn?" host=":"", hn?hn:"", (unsigned long long)n.x[30]); }
    pthread_mutex_lock(&oop_once_lock);
    st=g==OOP_GATE_OK?2:0;   /* a failed routine leaves it not started, as a cancelled one does */
    ok=bb_write(d->engine,ctl,&st,4) && g==OOP_GATE_OK;
    pthread_cond_broadcast(&oop_once_cv);
    pthread_mutex_unlock(&oop_once_lock);
    *result=0; return ok;
}
/* ------------------------------------------------- qsort / bsearch
 * The comparator is guest code: each comparison is a nested guest call on
 * this thread (below its suspended frame) on pointers to the elements where
 * they lie. qsort orders an index array (merge sort), then writes the
 * permuted elements back in one bounded write. A failed comparator stops the
 * guest; it is never taken as "equal". */
typedef struct { oop_domain *d; uint64_t cmp, tls, sp; bool failed; } oop_cmp;
static int oop_compare(oop_cmp *c, uint64_t a, uint64_t b) {
    if (c->failed) return 0;
    bb_state n={0}; bb_result gr; n.sp=c->sp; n.tpidr_el0=c->tls; n.x[0]=a; n.x[1]=b;
    if (oop_domain_call(c->d,c->cmp,OOP_ABI_INTEGER_0_TO_8,&n,100000000u,&gr)!=OOP_GATE_OK) { c->failed=true; return 0; }
    return (int)(int32_t)n.x[0];
}
static void oop_merge(oop_cmp *c, uint64_t base, size_t size, size_t *idx, size_t *tmp, size_t n) {
    if (n<2 || c->failed) return;
    size_t h=n/2; oop_merge(c,base,size,idx,tmp,h); oop_merge(c,base,size,idx+h,tmp,n-h);
    size_t i=0,j=h,k=0;
    while (i<h && j<n) tmp[k++]=oop_compare(c,base+idx[j]*size,base+idx[i]*size)<0?idx[j++]:idx[i++];
    while (i<h) tmp[k++]=idx[i++];
    while (j<n) tmp[k++]=idx[j++];
    memcpy(idx,tmp,n*sizeof(*idx));
}
static bool oop_cmp_setup(oop_domain *d, const bb_state *s, uint64_t cmp, oop_cmp *c) {
    *c=(oop_cmp){.d=d,.cmp=cmp,.tls=s->tpidr_el0};
    return oop_domain_reentry_stack(d,&c->sp) && oop_domain_register_entry(d,cmp);
}
static bool oop_qsort_gate(const bb_state *s, uint64_t *result, void *opaque) {
    oop_domain *d=opaque; uint64_t base=s->x[0], n=s->x[1], size=s->x[2]; oop_cmp c;
    *result=0;
    if (n<2 || !size) return true;
    if (n>(1u<<24) || size>(1u<<16) || n*size>(UINT64_C(1)<<30) || !bb_access(d->engine,base,(size_t)(n*size),BB_R|BB_W) || !oop_cmp_setup(d,s,s->x[3],&c)) return false;
    size_t *idx=malloc((size_t)n*sizeof(size_t)*2); uint8_t *copy=malloc((size_t)(n*size)), *out=malloc((size_t)(n*size));
    bool ok=idx && copy && out && bb_read(d->engine,base,copy,(size_t)(n*size));
    if (ok) { for (size_t i=0;i<n;i++) idx[i]=i; oop_merge(&c,base,(size_t)size,idx,idx+n,(size_t)n); ok=!c.failed; }
    if (ok) { for (size_t i=0;i<n;i++) memcpy(out+i*size,copy+idx[i]*size,(size_t)size); ok=bb_write(d->engine,base,out,(size_t)(n*size)); }
    free(idx); free(copy); free(out); return ok;
}
static bool oop_bsearch_gate(const bb_state *s, uint64_t *result, void *opaque) {
    oop_domain *d=opaque; uint64_t key=s->x[0], base=s->x[1], n=s->x[2], size=s->x[3]; oop_cmp c;
    *result=0;
    if (!n || !size) return true;
    if (n*size>(UINT64_C(1)<<30) || !bb_access(d->engine,base,(size_t)(n*size),BB_R) || !oop_cmp_setup(d,s,s->x[4],&c)) return false;
    uint64_t lo=0,hi=n;
    while (lo<hi) { uint64_t mid=lo+(hi-lo)/2; int r=oop_compare(&c,key,base+mid*size); if (c.failed) return false;
        if (!r) { *result=base+mid*size; return true; } if (r<0) hi=mid; else lo=mid+1; }
    return true;
}
/* Guest Linux system calls (SVC #0): the callback gets the number (x8) and
 * the arguments (x0-x5) and returns the Linux result (a value or -errno);
 * false stops the guest. */
static oop_syscall_fn g_syscall_fn; static void *g_syscall_opaque;
static bool domain_svc(bb_state *s, void *opaque) {
    (void)opaque; int64_t r;
    if (!g_syscall_fn || !g_syscall_fn(s,(long)s->x[8],&r,g_syscall_opaque)) return false;
    s->x[0]=(uint64_t)r; return true;
}
bool oop_domain_set_syscall(oop_domain *d, oop_syscall_fn fn, void *opaque) {
    if (!d || !fn) return false;
    g_syscall_opaque=opaque; g_syscall_fn=fn;
    return bb_set_svc_handler(d->engine,domain_svc,d);
}
bool oop_domain_register_sort(oop_domain *d, uint64_t qsort_fn, uint64_t bsearch_fn) {
    return d && (!qsort_fn || oop_domain_register_host(d,qsort_fn,oop_qsort_gate,d)) && (!bsearch_fn || oop_domain_register_host(d,bsearch_fn,oop_bsearch_gate,d));
}
bool oop_domain_register_once(oop_domain *d, uint64_t pthread_once_fn) {
    return d && pthread_once_fn && oop_domain_register_host(d,pthread_once_fn,oop_once_gate,d);
}
bool oop_domain_register_setjmp(oop_domain *d, uint64_t setjmp_fn, uint64_t sigsetjmp_fn, uint64_t longjmp_fn, uint64_t siglongjmp_fn) {
    if (!d) return false;
    uint64_t sets[2]={setjmp_fn,sigsetjmp_fn}, jumps[2]={longjmp_fn,siglongjmp_fn};
    for (int i=0;i<2;i++) if (sets[i] && !oop_domain_register_host(d,sets[i],oop_setjmp_gate,d)) return false;
    for (int i=0;i<2;i++) if (jumps[i] && !oop_domain_register_host(d,jumps[i],oop_longjmp_gate,d)) return false;
    return true;
}
bool oop_domain_return_fp(oop_domain *d, uint64_t bits) {
    oop_thread *t=d?pthread_getspecific(d->tkey):NULL;
    if (!t || !t->host_result) return false;
    t->host_result->v[0][0]=bits; t->host_result->v[0][1]=0; return true;
}
bool oop_domain_reentry_stack(const oop_domain *d, uint64_t *sp) {
    if (!d || !sp) return false;
    oop_thread *t=pthread_getspecific(d->tkey);
    if (!t || !t->depth || !t->host_state || t->host_stack<256) return false;
    *sp=(t->host_stack-256)&~UINT64_C(15); return true;
}
oop_domain *oop_domain_create(bb_engine *engine) {
    if (!engine || bb_access(engine,RETURN_PC,1,0)) return NULL;
    oop_domain *d=calloc(1,sizeof(*d)); if (!d) return NULL;
    d->engine=engine;
    if (pthread_mutex_init(&d->reg_lock,NULL) || pthread_key_create(&d->tkey,thread_ctx_free)) { free(d); return NULL; }
    return d;
}
bool oop_domain_enable_threads(oop_domain *d) {
    if (!d || d->threaded) return false;
    if (!bb_enable_threads(d->engine)) return false;
    d->threaded=true; return true;
}
void oop_domain_destroy(oop_domain *d) {
    if (!d) return;
    if (d->host_count) bb_clear_host_gate(d->engine,host_transition,d);
    oop_thread *t=pthread_getspecific(d->tkey); if (t) { pthread_setspecific(d->tkey,NULL); thread_ctx_free(t); }
    pthread_key_delete(d->tkey); pthread_mutex_destroy(&d->reg_lock);
    free(d->hosts); free(d->entries); free(d);
}
bool oop_domain_register_entry(oop_domain *d, uint64_t pc) {
    if (!d || (pc&3) || !bb_access(d->engine,pc,4,BB_X)) return false;
    if (d->threaded) pthread_mutex_lock(&d->reg_lock);
    bool r=true;
    size_t lo=0,hi=d->count;
    while (lo<hi) { size_t m=lo+(hi-lo)/2; if (d->entries[m]<pc) lo=m+1; else hi=m; }
    if (lo<d->count && d->entries[lo]==pc) goto out;      /* already present */
    if (d->count==ENTRY_LIMIT) { r=false; goto out; }
    if (d->count==d->capacity) {
        size_t cap=d->capacity ? d->capacity*2 : 32;
        uint64_t *entries=realloc(d->entries,cap*sizeof(*entries));
        if (!entries) { r=false; goto out; }
        d->entries=entries; d->capacity=cap;
    }
    memmove(d->entries+lo+1,d->entries+lo,(d->count-lo)*sizeof(*d->entries));
    d->entries[lo]=pc; ++d->count;
out:
    if (d->threaded) pthread_mutex_unlock(&d->reg_lock);
    return r;
}
bool oop_domain_register_host(oop_domain *d, uint64_t token, oop_host_callback fn, void *opaque) {
    if (!d || !fn || token==RETURN_PC || d->host_count==HOST_LIMIT) return false;
    if (d->threaded) pthread_mutex_lock(&d->reg_lock);
    bool r=true;
    size_t lo=0,hi=d->host_count;
    while (lo<hi) { size_t m=lo+(hi-lo)/2; if (d->hosts[m].token<token) lo=m+1; else hi=m; }
    if (lo<d->host_count && d->hosts[lo].token==token) { r=false; goto out; }
    if (d->host_count==d->host_capacity) {
        size_t cap=d->host_capacity ? d->host_capacity*2 : 16;
        host_entry *hosts=realloc(d->hosts,cap*sizeof(*hosts)); if (!hosts) { r=false; goto out; }
        d->hosts=hosts; d->host_capacity=cap;
    }
    if (!bb_set_host_gate(d->engine,token,host_transition,d)) { r=false; goto out; }
    memmove(d->hosts+lo+1,d->hosts+lo,(d->host_count-lo)*sizeof(*d->hosts));
    d->hosts[lo]=(host_entry){token,fn,opaque}; ++d->host_count;
out:
    if (d->threaded) pthread_mutex_unlock(&d->reg_lock);
    return r;
}
bool oop_domain_host_registered(oop_domain *d, uint64_t token) {
    if (!d) return false;
    if (d->threaded) pthread_mutex_lock(&d->reg_lock);
    size_t lo=0,hi=d->host_count;
    while (lo<hi) { size_t m=lo+(hi-lo)/2; if (d->hosts[m].token<token) lo=m+1; else hi=m; }
    bool r=lo<d->host_count && d->hosts[lo].token==token;
    if (d->threaded) pthread_mutex_unlock(&d->reg_lock);
    return r;
}
oop_gate_result oop_domain_call(oop_domain *d, uint64_t pc, oop_abi abi, bb_state *s, size_t budget, bb_result *gr) {
    if (gr) *gr=BB_INTERNAL;
    if (!d || !s || !gr || !budget) return OOP_GATE_ARGUMENT;
    /* The caller places every argument: x0-x7, v0-v7 in state, and for
     * OOP_ABI_STACK_ARGS the 8-byte slots at the guest SP it supplies. */
    if (abi!=OOP_ABI_INTEGER_0_TO_8 && abi!=OOP_ABI_FP_SIMD && abi!=OOP_ABI_STACK_ARGS) return OOP_GATE_ABI_UNSUPPORTED;
    if (d->threaded) pthread_mutex_lock(&d->reg_lock);
    size_t lo=0,hi=d->count;
    while (lo<hi) { size_t m=lo+(hi-lo)/2; if (d->entries[m]<pc) lo=m+1; else hi=m; }
    bool registered = lo<d->count && d->entries[lo]==pc;
    if (d->threaded) pthread_mutex_unlock(&d->reg_lock);
    if (!registered || !bb_access(d->engine,pc,4,BB_X)) return OOP_GATE_UNREGISTERED;
    if ((s->sp&15) || s->sp<16 || !bb_access(d->engine,s->sp-16,16,BB_R|BB_W)) return OOP_GATE_ARGUMENT;
    oop_thread *t=thread_ctx(d); if (!t) return OOP_GATE_ARGUMENT;
    /* A re-entry on this thread may use only space below its own suspended,
     * downward-growing stack. Different threads have independent stacks and do
     * not constrain one another. */
    if (t->depth>=16 || (t->depth && (!t->host_state || s==t->host_state ||
        t->host_stack<16 || s->sp>t->host_stack-16))) return OOP_GATE_ARGUMENT;
    /* AAPCS64 callee-saved: x19-x29, d8-d15, SP. x18 is the platform register,
     * a temporary for code built without -ffixed-x18 (this game's toolchain);
     * the host never reads the guest's x18, so it is not checked. */
    uint64_t preserved[11]; for (size_t i=0;i<11;++i) preserved[i]=s->x[19+i];
    uint64_t preserved_fp[8]; for (size_t i=0;i<8;++i) preserved_fp[i]=s->v[8+i][0];
    uint64_t sp=s->sp, tls=s->tpidr_el0;
    s->pc=pc; s->x[30]=RETURN_PC; s->exclusive_valid=false;
    ++t->depth;
#ifdef BB_TESTING
    *gr=d->reference ? bb_run_reference(d->engine,s,RETURN_PC,budget) : bb_run(d->engine,s,RETURN_PC,budget);
#else
    *gr=bb_run(d->engine,s,RETURN_PC,budget);
#endif
    --t->depth;
    s->exclusive_valid=false;
    if (*gr!=BB_STOP) {
        if (*gr==BB_MEMORY && !bb_access(d->engine,s->pc,1,0)) return OOP_GATE_UNKNOWN_TARGET;
        return OOP_GATE_GUEST_ERROR;
    }
    if (s->sp!=sp || s->tpidr_el0!=tls) return OOP_GATE_ABI_VIOLATION;
    for (size_t i=0;i<11;++i) if (s->x[19+i]!=preserved[i]) return OOP_GATE_ABI_VIOLATION;
    for (size_t i=0;i<8;++i) if (s->v[8+i][0]!=preserved_fp[i]) return OOP_GATE_ABI_VIOLATION;
    return OOP_GATE_OK;
}

/* Validate both the pointer vectors and strings before allowing a guest
 * constructor to observe them. No host pointer is passed to guest code. */
static bool guest_string(bb_engine *e, uint64_t p) {
    if (!p) return false;
    for (size_t i=0;i<4096;i++) {
        unsigned char c;
        if (p>UINT64_MAX-i || !bb_read(e,p+i,&c,1)) return false;
        if (!c) return true;
    }
    return false;
}
static bool guest_vector(bb_engine *e, uint64_t p, size_t count, bool exact) {
    if (!p || (p&7)) return false;
    for (size_t i=0;i<=count;i++) {
        uint64_t entry;
        if (p>UINT64_MAX-i*8 || !bb_read(e,p+i*8,&entry,8)) return false;
        if (!entry) return !exact || i==count;
        if (i==count || !guest_string(e,entry)) return false;
    }
    return false;
}
bool oop_domain_init_gate(tl_lib *owner, uintptr_t entry, int argc,
                          char **argv, char **envp, void *opaque) {
    (void)argv; (void)envp;
    oop_init_context *c=opaque;
    if (!c) return false;
    c->gate_result=OOP_GATE_ARGUMENT; c->guest_result=BB_INTERNAL;
    memset(&c->last_state,0,sizeof(c->last_state));
    if (!owner || !c->domain || argc<0 || argc>128 || !c->budget ||
        !c->tls || !bb_access(c->domain->engine,c->tls,0x30,BB_R|BB_W) ||
        !guest_vector(c->domain->engine,c->argv,(size_t)argc,true) ||
        !guest_vector(c->domain->engine,c->envp,128,false)) return false;
    if (!oop_domain_register_entry(c->domain,entry)) { c->gate_result=OOP_GATE_UNREGISTERED; return false; }
    bb_state s={0}; s.sp=c->stack; s.tpidr_el0=c->tls;
    s.x[0]=(uint64_t)argc; s.x[1]=c->argv; s.x[2]=c->envp;
    c->gate_result=oop_domain_call(c->domain,entry,OOP_ABI_INTEGER_0_TO_8,&s,c->budget,&c->guest_result);
    c->last_state=s;
    return c->gate_result==OOP_GATE_OK;
}
#ifdef BB_TESTING
void oop_domain_test_reference(oop_domain *d, bool enabled) { if (d) d->reference=enabled; }
#endif
#endif
