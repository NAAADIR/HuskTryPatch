/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Restricted, per-thread guest view of Husk's actual JNI VM.
 *
 * Threading model (documented policy):
 *  - One guest JavaVM for the bridge (JNI's JavaVM is process-wide). Each host
 *    thread that enters the guest gets its own guest JNIEnv view (a 16-byte
 *    guest struct pointing at the shared guest function table), its own guest
 *    TLS block and, unless it brings its own, its own guest stack. A gate
 *    accepts a call only from the thread owning that JNIEnv and TLS.
 *  - The host JNIEnv is resolved live for the calling thread on every call
 *    (tl_jni_env()); nothing caches another thread's env. Husk's pending
 *    exception is thread-local (t_pending), so exceptions stay per thread.
 *  - The reference, method and UTF tables are shared and guarded by one mutex
 *    that is held only for table bookkeeping, never across a Java call, a
 *    host JNI function that may run Java, or a guest call.
 *  - Local references are owned by the creating thread and by the native frame
 *    that made them; another thread's local is refused. Global references are
 *    usable from every attached thread. Reference slots are reused with a
 *    12-bit generation, so a deleted or stale token is refused (a stale token
 *    can only alias after 4095 reuses of the same slot).
 *  - Guest instruction execution remains serialized per engine (bb_enable_threads);
 *    host callbacks overlap. No parallel guest execution is claimed.
 */
#ifndef HUSK_OOP_JNI_GATE_H
#define HUSK_OOP_JNI_GATE_H
#include "husk-oop-domain.h"
#include "husk-tl-jni.h"
#include "husk-tl-jni-internal.h"
#include "husk-tl-dvm.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define JNI_VM_TOKEN_BASE UINT64_C(0xfffffff100000000)
#define JNI_ENV_TOKEN_BASE UINT64_C(0xfffffff200000000)
#define JNI_REF_TOKEN_BASE UINT64_C(0xfffffff300000000)
#define JNI_METHOD_TOKEN_BASE UINT64_C(0xfffffff400000000)
#define JNI_REF_LIMIT 65536u
#define JNI_REF_GENERATIONS 4096u
#define JNI_METHOD_LIMIT 4096u
#define JNI_UTF_LIMIT 64u
#define JNI_FIELD_LIMIT 4096u
#define JNI_THREAD_LIMIT 16u
#define JNI_TLS_BYTES 4096u
#define JNI_GUEST_STACK_BYTES (1u<<20)
typedef struct {
    void *host; uint32_t gen, frame; int32_t prev, next; int16_t owner; bool global, live;
} jni_ref_entry;
/* A guest copy of GetStringUTFChars' host buffer, released by its pointer. */
typedef struct { uint64_t guest; const char *host; void *string; } jni_utf_entry;
struct jni_gate;
typedef struct jni_thread {
    struct jni_gate *gate; pthread_t thread; bool used, provisioned; int16_t id;
    uint64_t env, tls, stack;                    /* guest JNIEnv*, TPIDR_EL0, highest SP */
    uint64_t env_alloc, tls_alloc, stack_alloc;  /* guest heap blocks this bridge owns */
    int32_t locals;                              /* newest live local of this thread, -1 none */
    uint32_t frame;                              /* Java-to-guest native frame depth */
    unsigned native_calls; oop_gate_result native_gate; bb_result native_guest; bb_state native_state;
} jni_thread;
typedef struct jni_gate {
    bb_engine *engine; oop_domain *domain;
    /* The opening (primary) thread: its env/tls stay here for existing callers. */
    pthread_t thread; uint64_t tls, env;
    uint64_t allocation, vm, vm_table, env_table;
    void *host_vm;
    int32_t (*getenv_fn)(void *,void **,int32_t);
    const void *const *env_fns;     /* Husk's one function table, checked on every call */
    pthread_mutex_t lock; pthread_key_t key; bool key_ok, threaded;
    jni_ref_entry *refs; size_t ref_count; int32_t free_ref; size_t live_refs;
    tl_jmeth *methods[JNI_METHOD_LIMIT]; size_t method_count;
    jni_utf_entry utf[JNI_UTF_LIMIT];
    struct { uint64_t guest; void *array; const void *host; size_t bytes; unsigned kind; } elems[JNI_UTF_LIMIT];
    tl_jfield *fields[JNI_FIELD_LIMIT]; size_t field_count;
    jni_thread threads[JNI_THREAD_LIMIT];
    /* Java-to-guest natives (tl_dvm_set_foreign_natives) */
    tl_lib *lib; uint64_t stack; size_t budget;
    _Atomic unsigned native_calls, utf_gets, utf_releases, attach_calls, threads_provisioned, threads_exited;
    _Atomic unsigned cross_thread_refusals, max_in_gate; _Atomic unsigned in_gate;
    char last_native[200];
    struct { uint64_t pc; char symbol[200]; unsigned calls, ok, failed; oop_gate_result gate; bb_result guest; bb_state stop; char why[64];
             unsigned first_call; oop_gate_result first_gate; bb_result first_guest; bb_state first_stop, first_entry; } native_names[128];
    size_t native_name_count;
    oop_gate_result native_gate; bb_result native_guest; bb_state native_state;
    _Atomic unsigned get_env_calls, find_class_calls, object_class_calls, global_ref_calls, method_calls, object_calls, string_calls;
    _Atomic unsigned static_calls, instance_calls, exception_checks, exception_clears, exception_throws;
    char last_class[128], last_name[64], last_sig[128];
    jvalue last_args[4];
    /* Diagnostics only (NULL in production): runs on the calling thread inside
     * a guest Call*Method gate, with the guest suspended, no bridge lock and
     * no engine lock held, just before the Java method runs. */
    void (*call_hook)(struct jni_gate *, const jni_thread *, void *); void *call_hook_opaque;
    char refusal[256];   /* the most recent refused Call*Method and the check that refused it */
} jni_gate;
static bool jni_refuse(jni_gate *j,const tl_jmeth *m,const char *why) {
    pthread_mutex_lock(&j->lock);
    snprintf(j->refusal,sizeof(j->refusal),"%s%s%s%s: %s",m&&m->cls&&m->cls->name?m->cls->name:"",m?".":"",m?m->name:"",m?m->sig:"",why);
    if (why && !strcmp(why,"pending exception") && tl_jni_pending()) {
        size_t n=strlen(j->refusal); char b[160]; snprintf(j->refusal+n,sizeof(j->refusal)-n," [%s]",tl_dvm_running()?tl_dvm_describe_pending(b,sizeof(b)):"?"); }
    pthread_mutex_unlock(&j->lock); return false;
}
/* The calling thread's live host JNIEnv; refused if it is not Husk's table. */
static void *jni_host_env(const jni_gate *j) {
    void *env=tl_jni_env();
    return env && *(const void *const *const *)env==j->env_fns ? env : NULL;
}
static jni_thread *jni_self(jni_gate *j) { return j && j->key_ok ? pthread_getspecific(j->key) : NULL; }
/* The gate caller must be the thread owning this JNIEnv and TLS. */
static jni_thread *jni_thread_of(jni_gate *j,const bb_state *s) {
    jni_thread *t=jni_self(j);
    if (!t || s->tpidr_el0!=t->tls || s->x[0]!=t->env || !pthread_equal(t->thread,pthread_self())) return NULL;
    return t;
}
/* Concurrency observation: how many threads are inside JNI gates at once. */
static void jni_enter(jni_gate *j) {
    unsigned n=atomic_fetch_add(&j->in_gate,1)+1, m=atomic_load(&j->max_in_gate);
    while (n>m && !atomic_compare_exchange_weak(&j->max_in_gate,&m,n)) {}
}
static void jni_leave(jni_gate *j) { atomic_fetch_sub(&j->in_gate,1); }
static bool jni_guest_string(jni_gate *j,uint64_t p) {
    for (size_t i=0;i<4096;i++) { unsigned char ch;
        if (p>UINT64_MAX-i || !bb_read(j->engine,p+i,&ch,1)) return false;
        if (!ch) return true;
    }
    return false;
}
static uint64_t jni_token(size_t idx,uint32_t gen) { return JNI_REF_TOKEN_BASE+(((uint64_t)gen<<16)|idx)*16; }
static bool jni_decode(const jni_gate *j,uint64_t token,size_t *idx) {
    if (token<JNI_REF_TOKEN_BASE || (token-JNI_REF_TOKEN_BASE)%16) return false;
    uint64_t v=(token-JNI_REF_TOKEN_BASE)/16; size_t i=(size_t)(v&0xffff); uint32_t gen=(uint32_t)(v>>16);
    if (gen==0 || gen>=JNI_REF_GENERATIONS || i>=j->ref_count || !j->refs[i].live || j->refs[i].gen!=gen) return false;
    *idx=i; return true;
}
/* Caller holds j->lock. Local entries must belong to t. */
static bool jni_ref_lookup_locked(jni_gate *j,const jni_thread *t,uint64_t token,void **host,size_t *at) {
    size_t i; if (!jni_decode(j,token,&i)) return false;
    if (!j->refs[i].global && (!t || j->refs[i].owner!=t->id)) { atomic_fetch_add(&j->cross_thread_refusals,1); return false; }
    *host=j->refs[i].host; if (at) *at=i; return true;
}
static bool jni_ref_lookup(jni_gate *j,const jni_thread *t,uint64_t token,void **host) {
    if (!token) { *host=NULL; return true; }
    pthread_mutex_lock(&j->lock); bool ok=jni_ref_lookup_locked(j,t,token,host,NULL); pthread_mutex_unlock(&j->lock);
    return ok;
}
/* For callers outside a gate (tests): resolve as the calling thread. */
static bool jni_ref_get(jni_gate *j,uint64_t token,void **host) { return jni_ref_lookup(j,jni_self(j),token,host); }
static bool jni_ref_global(jni_gate *j,uint64_t token) {
    size_t i; pthread_mutex_lock(&j->lock); bool g=jni_decode(j,token,&i) && j->refs[i].global; pthread_mutex_unlock(&j->lock); return g;
}
static void jni_unlink_locked(jni_gate *j,jni_thread *t,size_t i) {
    jni_ref_entry *e=&j->refs[i];
    if (e->prev>=0) j->refs[e->prev].next=e->next; else if (t && t->locals==(int32_t)i) t->locals=e->next;
    if (e->next>=0) j->refs[e->next].prev=e->prev;
    e->prev=e->next=-1;
}
static void jni_free_slot_locked(jni_gate *j,size_t i) {
    j->refs[i].live=false; j->refs[i].host=NULL; j->refs[i].next=j->free_ref; j->free_ref=(int32_t)i; --j->live_refs;
}
/* A new token for a host reference this bridge now owns. */
static bool jni_ref_put(jni_gate *j,jni_thread *t,void *host,bool global,uint64_t *result) {
    if (!host) { *result=0; return true; }
    if (!global && !t) return false;
    pthread_mutex_lock(&j->lock);
    size_t i;
    if (j->free_ref>=0) { i=(size_t)j->free_ref; j->free_ref=j->refs[i].next; }
    else if (j->ref_count<JNI_REF_LIMIT) i=j->ref_count++;
    else { pthread_mutex_unlock(&j->lock); return false; }
    jni_ref_entry *e=&j->refs[i]; uint32_t gen=e->gen%(JNI_REF_GENERATIONS-1)+1;
    *e=(jni_ref_entry){.host=host,.gen=gen,.prev=-1,.next=-1,.owner=global?-1:t->id,.global=global,.live=true};
    if (!global) { e->frame=t->frame; e->next=t->locals; if (t->locals>=0) j->refs[t->locals].prev=(int32_t)i; t->locals=(int32_t)i; }
    ++j->live_refs; *result=jni_token(i,gen);
    pthread_mutex_unlock(&j->lock); return true;
}
/* Release t's locals made in native frames at or above `frame`. The host
 * delete runs after the lock is dropped. */
static void jni_release_frame(jni_gate *j,jni_thread *t,uint32_t frame) {
    void *batch[64]; size_t n;
    void *env=jni_host_env(j); void (*del)(void *,void *)=(void (*)(void *,void *))j->env_fns[23];
    do {
        n=0; pthread_mutex_lock(&j->lock);
        while (n<64 && t->locals>=0 && j->refs[t->locals].frame>=frame) {
            size_t i=(size_t)t->locals; batch[n++]=j->refs[i].host; jni_unlink_locked(j,t,i); jni_free_slot_locked(j,i);
        }
        pthread_mutex_unlock(&j->lock);
        for (size_t k=0;k<n;k++) if (env) del(env,batch[k]);
    } while (n==64);
}
static bool jni_findclass_gate(const bb_state *s,uint64_t *result,void *opaque) {
    jni_gate *j=opaque; jni_thread *t=jni_thread_of(j,s); uint64_t p=s->x[1]; void *env=jni_host_env(j);
    if (!t || !env || !jni_guest_string(j,p)) return false;
    jni_enter(j);
    void *(*fn)(void *,const char *)=(void *(*)(void *,const char *))j->env_fns[6];
    void *ref=fn(env,(const char *)(uintptr_t)p); ++j->find_class_calls;
    jni_leave(j);
    return jni_ref_put(j,t,ref,false,result);
}
static bool jni_method_gate(const bb_state *s,uint64_t *result,void *opaque,bool is_static) {
    jni_gate *j=opaque; jni_thread *t=jni_thread_of(j,s); void *klass, *env=jni_host_env(j);
    if (!t || !env || !jni_ref_lookup(j,t,s->x[1],&klass) || !jni_guest_string(j,s->x[2]) || !jni_guest_string(j,s->x[3])) return false;
    void *(*fn)(void *,void *,const char *,const char *)=
        (void *(*)(void *,void *,const char *,const char *))j->env_fns[is_static?113:33];
    jni_enter(j);
    void *method=fn(env,klass,(const char *)(uintptr_t)s->x[2],(const char *)(uintptr_t)s->x[3]);
    jni_leave(j); ++j->method_calls;
    if (!method) { *result=0; return true; }
    /* jmethodIDs are process-wide: one token per method, shared by every thread. */
    pthread_mutex_lock(&j->lock); size_t idx=j->method_count;
    for (size_t i=0;i<j->method_count;i++) if (j->methods[i]==method) { idx=i; break; }
    if (idx==j->method_count) { if (idx>=JNI_METHOD_LIMIT) { pthread_mutex_unlock(&j->lock); return false; } j->methods[j->method_count++]=method; }
    pthread_mutex_unlock(&j->lock);
    *result=JNI_METHOD_TOKEN_BASE+idx*16; return true;
}
static bool jni_getmethod_gate(const bb_state *s,uint64_t *r,void *p) { return jni_method_gate(s,r,p,false); }
static bool jni_getstaticmethod_gate(const bb_state *s,uint64_t *r,void *p) { return jni_method_gate(s,r,p,true); }
/* JNI Call<T>Method slot families: T in table order, three slots each
 * (varargs, V, A). Instance calls start at 34, static calls at 114. */
static const char jni_call_kinds[]="LZBCSIJFDV";
/* The guest's AAPCS64 va_list, exactly as the guest stores it. The guest
 * passes a pointer to its own copy; it is never handed to a host va_arg. */
typedef struct { uint64_t stack, gr_top, vr_top; int32_t gr_offs, vr_offs; } jni_guest_va;
static bool jni_va_next(jni_gate *j,jni_guest_va *va,bool fp,uint64_t *out) {
    uint64_t at;
    if (!fp && va->gr_offs<0) {
        if (va->gr_offs<-64 || va->gr_offs%8 || va->gr_top<(uint64_t)-(int64_t)va->gr_offs) return false;
        at=va->gr_top-(uint64_t)-(int64_t)va->gr_offs; va->gr_offs+=8;
    } else if (fp && va->vr_offs<0) {
        if (va->vr_offs<-128 || va->vr_offs%16 || va->vr_top<(uint64_t)-(int64_t)va->vr_offs) return false;
        at=va->vr_top-(uint64_t)-(int64_t)va->vr_offs; va->vr_offs+=16;
    } else {
        /* Every JNI variadic argument is promoted to an 8-byte stack slot. */
        if ((va->stack&7) || va->stack>UINT64_MAX-8) return false;
        at=va->stack; va->stack+=8;
    }
    return bb_read(j->engine,at,out,8);
}
static bool jni_method_get(jni_gate *j,uint64_t token,tl_jmeth **m) {
    if (token<JNI_METHOD_TOKEN_BASE || (token-JNI_METHOD_TOKEN_BASE)%16) return false;
    uint64_t idx=(token-JNI_METHOD_TOKEN_BASE)/16;
    pthread_mutex_lock(&j->lock);
    bool ok=idx<j->method_count && j->methods[idx]; if (ok) *m=j->methods[idx];
    pthread_mutex_unlock(&j->lock); return ok;
}
/* Convert one guest argument slot to the host jvalue Husk's typed A-form
 * expects. Object arguments must be live tokens usable by this thread. */
static bool jni_arg(jni_gate *j,const jni_thread *t,char k,uint64_t raw,bool from_fp,jvalue *out) {
    out->j=0;
    switch (k) {
    case 'Z': out->z=(uint8_t)raw; return true;
    case 'B': out->b=(int8_t)raw; return true;
    case 'C': out->c=(uint16_t)raw; return true;
    case 'S': out->s=(int16_t)raw; return true;
    case 'I': out->i=(int32_t)raw; return true;
    case 'J': out->j=(int64_t)raw; return true;
    case 'F': case 'D': { double d; memcpy(&d,&raw,8);
        /* V/varargs promote float to double; the A form stores a raw jfloat. */
        if (k=='D') out->d=d; else if (from_fp) out->f=(float)d; else { uint32_t w=(uint32_t)raw; memcpy(&out->f,&w,4); }
        return true; }
    case 'L': { void *host; if (!jni_ref_lookup(j,t,raw,&host)) return false; out->l=host; return true; }
    default: return false;
    }
}
static bool jni_ret_fp(jni_gate *j,char k,jvalue v);
/* Generic Call[Static]<T>Method{V,A}. Dispatch goes through Husk's own
 * Call<T>MethodA, so the method runs as production runs it: an installed
 * host implementation, otherwise the Dalvik interpreter's bytecode. */
/* C variadic arguments after the method ID (AAPCS64): integers and pointers
 * continue in x3-x7, float/double (promoted to double) in v0-v7, the rest in
 * 8-byte slots from the caller's SP; everything is read from guest state. */
static bool jni_decode_variadic(jni_gate *j,const jni_thread *t,const tl_jmeth *m,const bb_state *s,jvalue *args) {
    if (m->nargs<0 || m->nargs>40) return false;
    unsigned gi=3, vi=0; uint64_t stack=s->sp;
    for (int i=0;i<m->nargs;i++) { uint64_t raw; bool fp=m->argk[i]=='F' || m->argk[i]=='D';
        if (!fp && gi<8) raw=s->x[gi++];
        else if (fp && vi<8) raw=s->v[vi++][0];
        else { if (!bb_read(j->engine,stack,&raw,8)) return false; stack+=8; }
        if (!jni_arg(j,t,m->argk[i],raw,fp,&args[i])) return false; }
    static _Atomic unsigned logged;
    if (atomic_fetch_add(&logged,1)<32) { void tl_log_line(const char *, ...);
        tl_log_line("oop: guest JNI %s %s.%s%s (variadic)",m->is_static?"static":"instance",m->cls&&m->cls->name?m->cls->name:"?",m->name,m->sig); }
    return true;
}
/* form: 0 = va_list (…V), 1 = jvalue array (…A), 2 = C variadic (…). */
static bool jni_call_gate(const bb_state *s,uint64_t *result,jni_gate *j,bool is_static,unsigned t,int form) {
    bool a_form=form==1;
    void *target; tl_jmeth *m; jvalue args[40]; jni_thread *th=jni_thread_of(j,s); void *env=jni_host_env(j);
    if (!th || !env || t>=10) return false;
    if (!jni_method_get(j,s->x[2],&m)) return jni_refuse(j,NULL,"unknown method token");
    if (tl_jni_pending()) return jni_refuse(j,m,"pending exception");
    if (!jni_ref_lookup(j,th,s->x[1],&target) || !target) return jni_refuse(j,m,"invalid class/object reference");
    if (!m->cls || m->is_static!=is_static) return jni_refuse(j,m,"static/instance mismatch");
    if (m->nargs<0 || m->nargs>(int)(sizeof(args)/sizeof(args[0])) || m->retk!=jni_call_kinds[t]) return jni_refuse(j,m,"return kind mismatch");
    /* Husk returns zero for a method nothing implements; never let that look
     * like a completed Java call. Require installed host code or bytecode. */
    if (!m->fn && !(m->dvm && tl_dvm)) return jni_refuse(j,m,"no implementation (no HLE code, no bytecode)");
    if (a_form) {
        if (m->nargs && (!s->x[3] || !bb_access(j->engine,s->x[3],(size_t)m->nargs*8,BB_R))) return false;
        for (int i=0;i<m->nargs;i++) { uint64_t raw;
            if (!bb_read(j->engine,s->x[3]+(uint64_t)i*8,&raw,8) || !jni_arg(j,th,m->argk[i],raw,false,&args[i])) return jni_refuse(j,m,"argument"); }
    } else if (form==2) {
        if (!jni_decode_variadic(j,th,m,s,args)) return jni_refuse(j,m,"argument");
    } else {
        jni_guest_va va;
        if (!s->x[3] || !bb_read(j->engine,s->x[3],&va,sizeof(va))) return false;
        for (int i=0;i<m->nargs;i++) { uint64_t raw; bool fp=m->argk[i]=='F' || m->argk[i]=='D';
            if (!jni_va_next(j,&va,fp,&raw) || !jni_arg(j,th,m->argk[i],raw,fp,&args[i])) return jni_refuse(j,m,"argument"); }
    }
    pthread_mutex_lock(&j->lock);
    memset(j->last_args,0,sizeof(j->last_args)); memcpy(j->last_args,args,(size_t)(m->nargs<4?m->nargs:4)*sizeof(jvalue));
    snprintf(j->last_class,sizeof(j->last_class),"%s",m->cls->name?m->cls->name:"?");
    snprintf(j->last_name,sizeof(j->last_name),"%s",m->name); snprintf(j->last_sig,sizeof(j->last_sig),"%s",m->sig);
    pthread_mutex_unlock(&j->lock);
    const void *fn=j->env_fns[(is_static?114:34)+t*3+2];
    uint64_t r=0; void *ref=NULL;
    /* No bridge lock is held while Java runs: it may re-enter the guest. */
    jni_enter(j);
    if (j->call_hook) j->call_hook(j,th,j->call_hook_opaque);
    switch (m->retk) {
    case 'V': ((void (*)(void *,void *,void *,const jvalue *))fn)(env,target,m,args); break;
    case 'Z': r=((uint8_t (*)(void *,void *,void *,const jvalue *))fn)(env,target,m,args); break;
    case 'B': r=(uint8_t)((int8_t (*)(void *,void *,void *,const jvalue *))fn)(env,target,m,args); break;
    case 'C': r=((uint16_t (*)(void *,void *,void *,const jvalue *))fn)(env,target,m,args); break;
    case 'S': r=(uint16_t)((int16_t (*)(void *,void *,void *,const jvalue *))fn)(env,target,m,args); break;
    case 'I': r=(uint32_t)((int32_t (*)(void *,void *,void *,const jvalue *))fn)(env,target,m,args); break;
    case 'J': r=(uint64_t)((int64_t (*)(void *,void *,void *,const jvalue *))fn)(env,target,m,args); break;
    case 'L': ref=((void *(*)(void *,void *,void *,const jvalue *))fn)(env,target,m,args); break;
    case 'F': { jvalue v; v.j=0; v.f=((float (*)(void *,void *,void *,const jvalue *))fn)(env,target,m,args); jni_leave(j); if (!jni_ret_fp(j,'F',v)) return false; jni_enter(j); break; }
    case 'D': { jvalue v; v.d=((double (*)(void *,void *,void *,const jvalue *))fn)(env,target,m,args); jni_leave(j); if (!jni_ret_fp(j,'D',v)) return false; jni_enter(j); break; }
    default: jni_leave(j); return false;
    }
    jni_leave(j);
    /* A throwing method returns null; a pending exception stays for the guest. */
    if (m->retk=='L' && !jni_ref_put(j,th,ref,false,&r)) return false;
    if (is_static) ++j->static_calls; else { ++j->instance_calls; if (m->retk=='L') ++j->object_calls; }
    if (tl_jni_pending()) ++j->exception_throws;
    *result=r; return true;
}
#define JNI_CALL_GATES(T,I) \
    static bool jni_call_v_##T(const bb_state *s,uint64_t *r,void *p) { return jni_call_gate(s,r,p,false,I,0); } \
    static bool jni_call_a_##T(const bb_state *s,uint64_t *r,void *p) { return jni_call_gate(s,r,p,false,I,1); } \
    static bool jni_call_c_##T(const bb_state *s,uint64_t *r,void *p) { return jni_call_gate(s,r,p,false,I,2); } \
    static bool jni_scall_v_##T(const bb_state *s,uint64_t *r,void *p) { return jni_call_gate(s,r,p,true,I,0); } \
    static bool jni_scall_a_##T(const bb_state *s,uint64_t *r,void *p) { return jni_call_gate(s,r,p,true,I,1); } \
    static bool jni_scall_c_##T(const bb_state *s,uint64_t *r,void *p) { return jni_call_gate(s,r,p,true,I,2); }
JNI_CALL_GATES(L,0) JNI_CALL_GATES(Z,1) JNI_CALL_GATES(B,2) JNI_CALL_GATES(C,3) JNI_CALL_GATES(S,4)
JNI_CALL_GATES(I,5) JNI_CALL_GATES(J,6) JNI_CALL_GATES(F,7) JNI_CALL_GATES(D,8) JNI_CALL_GATES(V,9)
#undef JNI_CALL_GATES
static bool jni_exceptioncheck_gate(const bb_state *s,uint64_t *result,void *opaque) {
    jni_gate *j=opaque; if (!jni_thread_of(j,s)) return false;
    *result=tl_jni_pending()?1:0; ++j->exception_checks; return true;
}
static bool jni_exceptionoccurred_gate(const bb_state *s,uint64_t *result,void *opaque) {
    jni_gate *j=opaque; jni_thread *t=jni_thread_of(j,s); void *env=jni_host_env(j); if (!t || !env) return false;
    void *(*fn)(void *)=(void *(*)(void *))j->env_fns[15];
    return jni_ref_put(j,t,fn(env),false,result);
}
static bool jni_exceptionclear_gate(const bb_state *s,uint64_t *result,void *opaque) {
    jni_gate *j=opaque; void *env=jni_host_env(j); if (!jni_thread_of(j,s) || !env) return false;
    void (*fn)(void *)=(void (*)(void *))j->env_fns[17]; fn(env);
    ++j->exception_clears; *result=0; return true;
}
static bool jni_objectclass_gate(const bb_state *s,uint64_t *result,void *opaque) {
    jni_gate *j=opaque; jni_thread *t=jni_thread_of(j,s); void *object, *env=jni_host_env(j);
    if (!t || !env || !jni_ref_lookup(j,t,s->x[1],&object)) return false;
    void *(*fn)(void *,void *)=(void *(*)(void *,void *))j->env_fns[31];
    void *ref=fn(env,object); ++j->object_class_calls;
    return jni_ref_put(j,t,ref,false,result);
}
static bool jni_newstringutf_gate(const bb_state *s,uint64_t *result,void *opaque) {
    jni_gate *j=opaque; jni_thread *t=jni_thread_of(j,s); void *env=jni_host_env(j);
    if (!t || !env || !jni_guest_string(j,s->x[1])) return false;
    void *(*fn)(void *,const char *)=(void *(*)(void *,const char *))j->env_fns[167];
    void *ref=fn(env,(const char *)(uintptr_t)s->x[1]); ++j->string_calls;
    return jni_ref_put(j,t,ref,false,result);
}
static bool jni_globalref_gate(const bb_state *s,uint64_t *result,void *opaque) {
    jni_gate *j=opaque; jni_thread *t=jni_thread_of(j,s); void *object, *env=jni_host_env(j);
    if (!t || !env || !jni_ref_lookup(j,t,s->x[1],&object)) return false;
    void *(*fn)(void *,void *)=(void *(*)(void *,void *))j->env_fns[21];
    void *ref=fn(env,object); ++j->global_ref_calls;
    return jni_ref_put(j,t,ref,true,result);
}
static bool jni_delete_ref(jni_gate *j,const bb_state *s,uint64_t *result,bool global) {
    jni_thread *t=jni_thread_of(j,s); void *env=jni_host_env(j), *object=NULL; size_t i;
    if (!t || !env) return false;
    if (s->x[1]) {
        pthread_mutex_lock(&j->lock);
        if (!jni_ref_lookup_locked(j,t,s->x[1],&object,&i) || j->refs[i].global!=global) { pthread_mutex_unlock(&j->lock); return false; }
        if (!global) jni_unlink_locked(j,t,i);
        jni_free_slot_locked(j,i);
        pthread_mutex_unlock(&j->lock);
        void (*fn)(void *,void *)=(void (*)(void *,void *))j->env_fns[global?22:23];
        fn(env,object);
    }
    *result=0; return true;
}
static bool jni_deleteglobal_gate(const bb_state *s,uint64_t *r,void *p) { return jni_delete_ref(p,s,r,true); }
static bool jni_deletelocal_gate(const bb_state *s,uint64_t *r,void *p) { return jni_delete_ref(p,s,r,false); }
static bool jni_getstringutfchars_gate(const bb_state *s,uint64_t *result,void *opaque) {
    jni_gate *j=opaque; jni_thread *t=jni_thread_of(j,s); void *str, *env=jni_host_env(j); size_t slot=JNI_UTF_LIMIT;
    if (!t || !env || !jni_ref_lookup(j,t,s->x[1],&str) || !str || tl_jni_pending() ||
        (s->x[2] && !bb_access(j->engine,s->x[2],1,BB_W))) return false;
    pthread_mutex_lock(&j->lock);
    for (size_t i=0;i<JNI_UTF_LIMIT;i++) if (!j->utf[i].guest && !j->utf[i].host) { slot=i; j->utf[i].host=""; break; }   /* reserved */
    pthread_mutex_unlock(&j->lock);
    if (slot==JNI_UTF_LIMIT) return false;
    const char *(*get)(void *,void *,uint8_t *)=(const char *(*)(void *,void *,uint8_t *))j->env_fns[169];
    void (*rel)(void *,void *,const char *)=(void (*)(void *,void *,const char *))j->env_fns[170];
    const char *host=get(env,str,NULL); uint64_t copy=0; bool ok=false;
    if (!host) { *result=0; ok=true; }   /* OutOfMemoryError or not a string: Husk's answer */
    else {
        size_t n=strnlen(host,1u<<24); copy=n<(1u<<24)?bb_heap_malloc(j->engine,n+1):0;
        uint8_t is_copy=1;
        ok=copy && bb_write(j->engine,copy,host,n+1) && (!s->x[2] || bb_write(j->engine,s->x[2],&is_copy,1));
        if (!ok) { if (copy) bb_heap_free(j->engine,copy); rel(env,str,host); copy=0; }
    }
    pthread_mutex_lock(&j->lock);
    j->utf[slot]=copy?(jni_utf_entry){copy,host,str}:(jni_utf_entry){0};
    pthread_mutex_unlock(&j->lock);
    if (copy) { ++j->utf_gets; *result=copy; }
    return ok;
}
static bool jni_releasestringutfchars_gate(const bb_state *s,uint64_t *result,void *opaque) {
    jni_gate *j=opaque; jni_thread *t=jni_thread_of(j,s); void *str, *env=jni_host_env(j);
    if (!t || !env || !jni_ref_lookup(j,t,s->x[1],&str) || !s->x[2]) return false;
    jni_utf_entry e={0};
    pthread_mutex_lock(&j->lock);
    for (size_t i=0;i<JNI_UTF_LIMIT;i++) if (j->utf[i].guest==s->x[2]) {
        if (j->utf[i].string==str) { e=j->utf[i]; j->utf[i]=(jni_utf_entry){0}; }
        break;
    }
    pthread_mutex_unlock(&j->lock);
    if (!e.guest) return false;
    void (*rel)(void *,void *,const char *)=(void (*)(void *,void *,const char *))j->env_fns[170];
    rel(env,str,e.host);
    if (!bb_heap_free(j->engine,e.guest)) return false;
    ++j->utf_releases; *result=0; return true;
}
/* ------------------------------------------------ the wider JNI surface
 * Arrays, fields, object construction, identity and type queries, string
 * lengths and regions, local frames. One dispatcher: the guest PC is the
 * slot's token. Every guest buffer is bounds-checked; element buffers are
 * guest-heap copies (the guest never sees a host pointer); host JNI functions
 * that may run Java are called without any bridge lock held. */
#define JNI_FIELD_TOKEN_BASE UINT64_C(0xfffffff500000000)
static const char jni_prim_kinds[]="ZBCSIJFD";
static const unsigned jni_prim_bytes[]={1,1,2,2,4,8,4,8};
static bool jni_field_get(jni_gate *j,uint64_t token,tl_jfield **f) {
    if (token<JNI_FIELD_TOKEN_BASE || (token-JNI_FIELD_TOKEN_BASE)%16) return false;
    uint64_t idx=(token-JNI_FIELD_TOKEN_BASE)/16;
    pthread_mutex_lock(&j->lock); bool ok=idx<j->field_count; if (ok) *f=j->fields[idx]; pthread_mutex_unlock(&j->lock);
    return ok;
}
static char jni_field_kind(const tl_jfield *f) { char k=f->sig?f->sig[0]:0; return k=='['||k=='L'?'L':k; }
static bool jni_ret_fp(jni_gate *j,char k,jvalue v) {
    uint64_t bits=0; if (k=='F') memcpy(&bits,&v.f,4); else memcpy(&bits,&v.d,8);
    return oop_domain_return_fp(j->domain,bits);
}
/* Decode a method's arguments from a guest va_list (a_form=false) or jvalue array. */
static bool jni_decode_args(jni_gate *j,const jni_thread *t,const tl_jmeth *m,uint64_t p,bool a_form,jvalue *args) {
    if (m->nargs<0 || m->nargs>40) return false;
    if (a_form) {
        if (m->nargs && (!p || !bb_access(j->engine,p,(size_t)m->nargs*8,BB_R))) return false;
        for (int i=0;i<m->nargs;i++) { uint64_t raw; if (!bb_read(j->engine,p+(uint64_t)i*8,&raw,8) || !jni_arg(j,t,m->argk[i],raw,false,&args[i])) return false; }
        return true;
    }
    jni_guest_va va; if (!p || !bb_read(j->engine,p,&va,sizeof(va))) return false;
    for (int i=0;i<m->nargs;i++) { uint64_t raw; bool fp=m->argk[i]=='F'||m->argk[i]=='D';
        if (!jni_va_next(j,&va,fp,&raw) || !jni_arg(j,t,m->argk[i],raw,fp,&args[i])) return false; }
    return true;
}
static bool jni_ext_gate(const bb_state *s,uint64_t *result,void *opaque) {
    jni_gate *j=opaque; jni_thread *t=jni_thread_of(j,s); void *env=jni_host_env(j);
    if (!t || !env || s->pc<JNI_ENV_TOKEN_BASE) return false;
    unsigned slot=(unsigned)((s->pc-JNI_ENV_TOKEN_BASE)/4); const void *fn=j->env_fns[slot]; bb_engine *e=j->engine;
    const uint64_t *x=s->x; void *a=NULL,*b=NULL; *result=0;
    if (!fn) return false;
    switch (slot) {
    case 10: /* GetSuperclass */ if (!jni_ref_lookup(j,t,x[1],&a) || !a) return false;
        return jni_ref_put(j,t,((void *(*)(void *,void *))fn)(env,a),false,result);
    case 11: /* IsAssignableFrom */ case 24: /* IsSameObject */ case 32: /* IsInstanceOf */
        if (!jni_ref_lookup(j,t,x[1],&a) || !jni_ref_lookup(j,t,x[2],&b)) return false;
        *result=((uint8_t (*)(void *,void *,void *))fn)(env,a,b); return true;
    case 16: /* ExceptionDescribe */ ((void (*)(void *))fn)(env); return true;
    case 19: /* PushLocalFrame: a frame of this thread's locals */
        if ((int32_t)x[1]<0) return false; ++t->frame; return true;
    case 20: { /* PopLocalFrame(result): drop the frame, keep result in the outer one */
        if (!t->frame || !jni_ref_lookup(j,t,x[1],&a)) return false;
        void *keep=a?tl_jni_ref(a):NULL;
        jni_release_frame(j,t,t->frame); --t->frame;
        return jni_ref_put(j,t,keep,false,result); }
    case 26: /* EnsureLocalCapacity */ return (int32_t)x[1]>=0;
    case 28: case 29: case 30: { /* NewObject (C variadic) / NewObjectV / NewObjectA */
        tl_jmeth *m; jvalue args[40];
        if (tl_jni_pending() || !jni_ref_lookup(j,t,x[1],&a) || !a || !jni_method_get(j,x[2],&m) || m->is_static ||
            strcmp(m->name,"<init>") || (!m->fn && !(m->dvm && tl_dvm)) ||
            !(slot==28?jni_decode_variadic(j,t,m,s,args):jni_decode_args(j,t,m,x[3],slot==30,args))) return false;
        jni_enter(j); void *o=((void *(*)(void *,void *,void *,const jvalue *))j->env_fns[30])(env,a,m,args); jni_leave(j);
        return jni_ref_put(j,t,o,false,result); }
    case 94: case 144: { /* GetFieldID / GetStaticFieldID */
        if (!jni_ref_lookup(j,t,x[1],&a) || !a || !jni_guest_string(j,x[2]) || !jni_guest_string(j,x[3])) return false;
        jni_enter(j); tl_jfield *f=((void *(*)(void *,void *,const char *,const char *))fn)(env,a,(const char *)(uintptr_t)x[2],(const char *)(uintptr_t)x[3]); jni_leave(j);
        if (!f) return true;   /* NoSuchFieldError pending, as Husk reports it */
        pthread_mutex_lock(&j->lock); size_t idx=j->field_count;
        for (size_t i=0;i<j->field_count;i++) if (j->fields[i]==f) { idx=i; break; }
        if (idx==j->field_count) { if (idx>=JNI_FIELD_LIMIT) { pthread_mutex_unlock(&j->lock); return false; } j->fields[j->field_count++]=f; }
        pthread_mutex_unlock(&j->lock);
        *result=JNI_FIELD_TOKEN_BASE+idx*16; return true; }
    case 164: case 168: /* GetStringLength / GetStringUTFLength */
        if (!jni_ref_lookup(j,t,x[1],&a) || !a) return false;
        *result=(uint32_t)((int32_t (*)(void *,void *))fn)(env,a); return true;
    case 171: /* GetArrayLength */
        if (!jni_ref_lookup(j,t,x[1],&a) || !a) return false;
        *result=(uint32_t)((int32_t (*)(void *,void *))fn)(env,a); return true;
    case 172: /* NewObjectArray(len, class, init) */
        if ((int32_t)x[1]<0 || !jni_ref_lookup(j,t,x[2],&a) || !a || !jni_ref_lookup(j,t,x[3],&b)) return false;
        return jni_ref_put(j,t,((void *(*)(void *,int32_t,void *,void *))fn)(env,(int32_t)x[1],a,b),false,result);
    case 173: /* GetObjectArrayElement */
        if (!jni_ref_lookup(j,t,x[1],&a) || !a) return false;
        return jni_ref_put(j,t,((void *(*)(void *,void *,int32_t))fn)(env,a,(int32_t)x[2]),false,result);
    case 174: /* SetObjectArrayElement */
        if (!jni_ref_lookup(j,t,x[1],&a) || !a || !jni_ref_lookup(j,t,x[3],&b)) return false;
        ((void (*)(void *,void *,int32_t,void *))fn)(env,a,(int32_t)x[2],b); return true;
    case 219: { /* GetJavaVM: the bridge's one guest JavaVM */
        void *out; if (!x[1] || !bb_host_data_alias(e,x[1],8,&out)) return false; memcpy(out,&j->vm,8); return true; }
    case 220: { /* GetStringUTFRegion(str, start, len, buf) */
        int32_t len=(int32_t)x[3]; if (len<0 || len>(1<<22) || !jni_ref_lookup(j,t,x[1],&a) || !a) return false;
        char *tmp=calloc((size_t)len*4+1,1); if (!tmp) return false;
        ((void (*)(void *,void *,int32_t,int32_t,char *))fn)(env,a,(int32_t)x[2],len,tmp);
        size_t n=strnlen(tmp,(size_t)len*4)+1; void *out;
        bool ok=tl_jni_pending() || (x[4] && bb_host_data_alias(e,x[4],n,&out) && (memcpy(out,tmp,n),true));
        free(tmp); return ok; }
    default: break;
    }
    if (slot>=175 && slot<=182) { /* New<Prim>Array(len) */
        if ((int32_t)x[1]<0) return false;
        return jni_ref_put(j,t,((void *(*)(void *,int32_t))fn)(env,(int32_t)x[1]),false,result);
    }
    if (slot>=199 && slot<=214) { /* Get/Set<Prim>ArrayRegion(array, start, len, buf) */
        unsigned k=(slot-199)%8; bool set=slot>=207; int32_t len=(int32_t)x[3];
        if (len<0 || !jni_ref_lookup(j,t,x[1],&a) || !a) return false;
        uint64_t n=(uint64_t)len*jni_prim_bytes[k]; void *buf=(void *)(uintptr_t)x[4];
        if (n) { if (set) { if (!bb_access(e,x[4],(size_t)n,BB_R)) return false; }
                 else if (!bb_host_data_alias(e,x[4],(size_t)n,&buf)) return false; }
        ((void (*)(void *,void *,int32_t,int32_t,void *))fn)(env,a,(int32_t)x[2],len,buf); return true;
    }
    if (slot>=183 && slot<=198) { /* Get/Release<Prim>ArrayElements: a guest-heap copy */
        unsigned k=(slot-183)%8; bool release=slot>=191;
        if (!jni_ref_lookup(j,t,x[1],&a) || !a) return false;
        if (!release) {
            int32_t len=((int32_t (*)(void *,void *))j->env_fns[171])(env,a); if (len<0) return false;
            size_t n=(size_t)len*jni_prim_bytes[k]; uint8_t is_copy=1;
            if (x[2] && !bb_host_data_alias(e,x[2],1,&b)) return false;
            const void *host=((const void *(*)(void *,void *,void *))fn)(env,a,NULL);
            if (!host) return true;
            uint64_t g=bb_heap_malloc(e,n?n:1);
            if (!g || (n && !bb_write(e,g,host,n))) { ((void (*)(void *,void *,const void *,int32_t))j->env_fns[191+k])(env,a,host,2); if (g) bb_heap_free(e,g); return false; }
            pthread_mutex_lock(&j->lock); size_t at=JNI_UTF_LIMIT;
            for (size_t i=0;i<JNI_UTF_LIMIT;i++) if (!j->elems[i].guest) { at=i; j->elems[i]=(typeof(j->elems[0])){g,a,host,n,k}; break; }
            pthread_mutex_unlock(&j->lock);
            if (at==JNI_UTF_LIMIT) { ((void (*)(void *,void *,const void *,int32_t))j->env_fns[191+k])(env,a,host,2); bb_heap_free(e,g); return false; }
            if (b) memcpy(b,&is_copy,1);
            *result=g; return true;
        }
        int32_t mode=(int32_t)x[3]; typeof(j->elems[0]) en={0};
        if (mode<0 || mode>2) return false;
        pthread_mutex_lock(&j->lock);
        for (size_t i=0;i<JNI_UTF_LIMIT;i++) if (j->elems[i].guest==x[2] && j->elems[i].array==a && j->elems[i].kind==k) { en=j->elems[i]; if (mode!=1) j->elems[i]=(typeof(j->elems[0])){0}; break; }
        pthread_mutex_unlock(&j->lock);
        if (!en.guest) return false;
        /* commit (0, JNI_COMMIT) copies the guest's edits back into the array */
        if (mode!=2 && en.bytes && !bb_read(e,en.guest,(void *)(uintptr_t)en.host,en.bytes)) return false;
        ((void (*)(void *,void *,const void *,int32_t))fn)(env,a,en.host,mode);
        if (mode!=1) bb_heap_free(e,en.guest);
        return true;
    }
    if ((slot>=95 && slot<=112) || (slot>=145 && slot<=162)) { /* Get/Set[Static]<T>Field */
        bool is_static=slot>=145; unsigned base=is_static?145:95; bool set=slot>=base+9; unsigned ti=(slot-base)%9;
        char k=ti==0?'L':jni_prim_kinds[ti-1]; tl_jfield *f;
        if (!jni_ref_lookup(j,t,x[1],&a) || !a || !jni_field_get(j,x[2],&f) || f->is_static!=is_static || jni_field_kind(f)!=k) return false;
        if (!set) {
            jvalue v; v.j=0;
            switch (k) {
            case 'L': return jni_ref_put(j,t,((void *(*)(void *,void *,void *))fn)(env,a,f),false,result);
            case 'Z': *result=((uint8_t (*)(void *,void *,void *))fn)(env,a,f); return true;
            case 'B': *result=(uint8_t)((int8_t (*)(void *,void *,void *))fn)(env,a,f); return true;
            case 'C': *result=((uint16_t (*)(void *,void *,void *))fn)(env,a,f); return true;
            case 'S': *result=(uint16_t)((int16_t (*)(void *,void *,void *))fn)(env,a,f); return true;
            case 'I': *result=(uint32_t)((int32_t (*)(void *,void *,void *))fn)(env,a,f); return true;
            case 'J': *result=(uint64_t)((int64_t (*)(void *,void *,void *))fn)(env,a,f); return true;
            case 'F': v.f=((float (*)(void *,void *,void *))fn)(env,a,f); return jni_ret_fp(j,'F',v);
            case 'D': v.d=((double (*)(void *,void *,void *))fn)(env,a,f); return jni_ret_fp(j,'D',v);
            }
            return false;
        }
        switch (k) {
        case 'L': if (!jni_ref_lookup(j,t,x[3],&b)) return false; ((void (*)(void *,void *,void *,void *))fn)(env,a,f,b); return true;
        case 'Z': ((void (*)(void *,void *,void *,uint8_t))fn)(env,a,f,(uint8_t)x[3]); return true;
        case 'B': ((void (*)(void *,void *,void *,int8_t))fn)(env,a,f,(int8_t)x[3]); return true;
        case 'C': ((void (*)(void *,void *,void *,uint16_t))fn)(env,a,f,(uint16_t)x[3]); return true;
        case 'S': ((void (*)(void *,void *,void *,int16_t))fn)(env,a,f,(int16_t)x[3]); return true;
        case 'I': ((void (*)(void *,void *,void *,int32_t))fn)(env,a,f,(int32_t)x[3]); return true;
        case 'J': ((void (*)(void *,void *,void *,int64_t))fn)(env,a,f,(int64_t)x[3]); return true;
        case 'F': { uint32_t u=(uint32_t)s->v[0][0]; float v; memcpy(&v,&u,4); ((void (*)(void *,void *,void *,float))fn)(env,a,f,v); return true; }
        case 'D': { double v; memcpy(&v,&s->v[0][0],8); ((void (*)(void *,void *,void *,double))fn)(env,a,f,v); return true; }
        }
        return false;
    }
    return false;
}
static bool jni_register_ext(jni_gate *j) {
    static const unsigned single[]={10,11,16,19,20,24,26,28,29,30,32,94,144,164,168,171,172,173,174,219,220};
    for (size_t i=0;i<sizeof(single)/sizeof(single[0]);i++)
        if (j->env_fns[single[i]] && !oop_domain_register_host(j->domain,JNI_ENV_TOKEN_BASE+single[i]*4,jni_ext_gate,j)) return false;
    for (unsigned s=175;s<=214;s++)
        if (j->env_fns[s] && !oop_domain_register_host(j->domain,JNI_ENV_TOKEN_BASE+s*4,jni_ext_gate,j)) return false;
    for (unsigned s=95;s<=112;s++)
        if (j->env_fns[s] && !oop_domain_register_host(j->domain,JNI_ENV_TOKEN_BASE+s*4,jni_ext_gate,j)) return false;
    for (unsigned s=145;s<=162;s++)
        if (j->env_fns[s] && !oop_domain_register_host(j->domain,JNI_ENV_TOKEN_BASE+s*4,jni_ext_gate,j)) return false;
    return true;
}
/* ----------------------------------------------------------- thread lifecycle */
static void jni_thread_release(jni_gate *j,jni_thread *t) {
    jni_release_frame(j,t,0);
    if (t->provisioned) {
        if (t->stack_alloc) bb_heap_free(j->engine,t->stack_alloc);
        if (t->tls_alloc) bb_heap_free(j->engine,t->tls_alloc);
        if (t->env_alloc) bb_heap_free(j->engine,t->env_alloc);
    }
    pthread_mutex_lock(&j->lock); *t=(jni_thread){0}; pthread_mutex_unlock(&j->lock);
}
/* Host thread exit: its locals and guest blocks go; globals stay. */
static void jni_thread_exit(void *p) {
    jni_thread *t=p; jni_gate *j=t?t->gate:NULL;
    if (!j) return;
    jni_thread_release(j,t); ++j->threads_exited;
}
static jni_thread *jni_slot_claim(jni_gate *j) {
    jni_thread *t=NULL;
    pthread_mutex_lock(&j->lock);
    for (unsigned i=0;i<JNI_THREAD_LIMIT;i++) if (!j->threads[i].used) {
        t=&j->threads[i]; *t=(jni_thread){.gate=j,.thread=pthread_self(),.used=true,.id=(int16_t)i,.locals=-1}; break; }
    pthread_mutex_unlock(&j->lock);
    return t;
}
/* Give the calling host thread its own guest JNIEnv view, TLS block (cloned
 * from the primary thread's, with its own self pointer) and guest stack.
 * Caller: not inside the guest on this thread. Refused unless threads are on. */
static jni_thread *jni_thread_provision(jni_gate *j) {
    if (!j || !j->threaded) return NULL;
    jni_thread *t=jni_self(j); if (t) return t;
    t=jni_slot_claim(j); if (!t) return NULL;
    t->provisioned=true;
    uint8_t tcb[JNI_TLS_BYTES];
    t->env_alloc=bb_heap_malloc(j->engine,16);
    t->tls_alloc=bb_heap_malloc(j->engine,JNI_TLS_BYTES+16);
    t->stack_alloc=bb_heap_malloc(j->engine,JNI_GUEST_STACK_BYTES);
    if (!t->env_alloc || !t->tls_alloc || !t->stack_alloc) goto fail;
    t->env=t->env_alloc; t->tls=(t->tls_alloc+15)&~UINT64_C(15);
    t->stack=(t->stack_alloc+JNI_GUEST_STACK_BYTES-64)&~UINT64_C(15);
    if (!bb_read(j->engine,j->tls,tcb,sizeof(tcb))) goto fail;
    memcpy(tcb,&t->tls,8);   /* TLS_SLOT_SELF names this thread's own block */
    if (!bb_write(j->engine,t->tls,tcb,sizeof(tcb)) || !bb_write(j->engine,t->env,&j->env_table,8) ||
        !oop_domain_thread_attach(j->domain,t->tls) || pthread_setspecific(j->key,t)) goto fail;
    ++j->threads_provisioned;
    return t;
fail:
    jni_thread_release(j,t); return NULL;
}
/* Turn on multithread entry: other host threads may then be provisioned when
 * they enter (Java-to-guest natives) or by jni_thread_provision. Call after
 * oop_domain_enable_threads, from the primary thread. */
static bool jni_gate_enable_threads(jni_gate *j) {
    if (!j || !j->allocation || j->threaded || !pthread_equal(j->thread,pthread_self())) return false;
    j->threaded=true; return true;
}
/* ---------------------------------------------- Java-to-guest natives */
/* The production interpreter's call_native hands the typed arguments here for
 * a symbol only the private image defines. */
static void *jni_foreign_resolve(void *opaque,const char *symbol) {
    jni_gate *j=opaque;
    if (!j || !j->lib) return NULL;
    void *p=tl_ld_sym(j->lib,symbol);
    if (!p || !bb_access(j->engine,(uintptr_t)p,4,BB_X)) return NULL;
    pthread_mutex_lock(&j->lock);
    bool known=false; for (size_t i=0;i<j->native_name_count;i++) known|=j->native_names[i].pc==(uintptr_t)p;
    if (!known && j->native_name_count<128) { memset(&j->native_names[j->native_name_count],0,sizeof(j->native_names[0]));
        j->native_names[j->native_name_count].pc=(uintptr_t)p;
        snprintf(j->native_names[j->native_name_count++].symbol,200,"%s",symbol); }
    pthread_mutex_unlock(&j->lock);
    return p;
}
/* First-fault report for a stopped Java-to-guest native: the stopping guest
 * PC, what it names (a guest image offset, or the host import it reached),
 * the return address, the instruction word when the PC is guest code, and
 * the argument registers. The engine does not record a data fault address. */
#ifdef HUSK_OOP_IOS_DIAG
const char *tl_bionic_name_of(const void *addr);
#endif
static void jni_report_stop(jni_gate *j,const jni_thread *t,const char *name,const char *why) {
    static _Atomic unsigned reported;
    if (!t || atomic_fetch_add(&reported,1)>=8) return;
    void tl_log_line(const char *, ...);
    const bb_state *s=&t->native_state; uint64_t base=j->lib?(uintptr_t)tl_ld_lib_base(j->lib):0, pc=s->pc, lr=s->x[30];
    const char *host=NULL; uint32_t w=0; bool code=bb_read(j->engine,pc,&w,4);
#ifdef HUSK_OOP_IOS_DIAG
    if (!code) host=tl_bionic_name_of((void *)(uintptr_t)pc);
#endif
    char where[96], ret[64];
    if (code && base && pc>=base && pc-base<(UINT64_C(1)<<28)) snprintf(where,sizeof(where),"game+%#llx word=%08x",(unsigned long long)(pc-base),w);
    else if (code) snprintf(where,sizeof(where),"guest %#llx word=%08x",(unsigned long long)pc,w);
    else snprintf(where,sizeof(where),"outside guest memory%s%s",host?", host import ":"",host?host:" (no bridged or named import)");
    if (base && lr>=base && lr-base<(UINT64_C(1)<<28)) snprintf(ret,sizeof(ret),"game+%#llx",(unsigned long long)(lr-base)); else snprintf(ret,sizeof(ret),"%#llx",(unsigned long long)lr);
    tl_log_line("oop: native %s stopped: %s gate=%d guest=%s pc=%#llx (%s) lr=%s sp=%#llx x0=%#llx x1=%#llx x2=%#llx fault_address=unavailable",
                name,why,t->native_gate,bb_result_name(t->native_guest),(unsigned long long)pc,where,ret,(unsigned long long)s->sp,
                (unsigned long long)s->x[0],(unsigned long long)s->x[1],(unsigned long long)s->x[2]);
}
static bool jni_foreign_fail(jni_gate *j,const jni_thread *t,const char *name,const char *why) {
    if (t && t->native_gate!=OOP_GATE_OK && t->native_gate!=OOP_GATE_ARGUMENT) jni_report_stop(j,t,name,why);
    char msg[300];
    snprintf(msg,sizeof(msg),"out-of-place native %s: %s (gate=%d guest=%s)",name,why,t?t->native_gate:OOP_GATE_ARGUMENT,bb_result_name(t?t->native_guest:BB_INTERNAL));
    tl_jni_throw("java/lang/InternalError",msg); return false;
}
static bool jni_foreign_call(void *opaque,void *fn,const char *shorty,jobj *target,const jvalue *args,int nargs,jvalue *ret) {
    jni_gate *j=opaque; char name[200]="?";
    pthread_mutex_lock(&j->lock);
    for (size_t i=0;i<j->native_name_count;i++) if (j->native_names[i].pc==(uintptr_t)fn) snprintf(name,sizeof(name),"%s",j->native_names[i].symbol);
    snprintf(j->last_native,sizeof(j->last_native),"%s",name);
    pthread_mutex_unlock(&j->lock);
    ret->j=0;
    jni_thread *t=j->allocation?jni_self(j):NULL;
    if (!t && j->allocation) t=jni_thread_provision(j);   /* a new Java thread entering, e.g. the GL thread */
    if (!t) return jni_foreign_fail(j,NULL,name,"called on a thread with no guest state");
    t->native_gate=OOP_GATE_ARGUMENT; t->native_guest=BB_INTERNAL;
    if (!shorty || nargs<0 || (int)strlen(shorty)!=nargs+1 || nargs>64) return jni_foreign_fail(j,t,name,"unsupported signature");
    if (!oop_domain_register_entry(j->domain,(uintptr_t)fn)) return jni_foreign_fail(j,t,name,"not a guest entry");
    void *env=jni_host_env(j); if (!env) return jni_foreign_fail(j,t,name,"no host JNIEnv on this thread");
    uint64_t sp=0;
    if (!oop_domain_reentry_stack(j->domain,&sp)) sp=t->stack?t->stack:j->stack;   /* not nested: the thread's own guest stack */
    uint32_t frame=++t->frame; uint64_t stk[64]; int ng=2,nf=0,ns=0; bool ok=false; const char *why="guest stopped";
    bool after=false; unsigned after_calls=0, after_ok=0, after_failed=0;
    bb_state s={0}, entry={0}; s.tpidr_el0=t->tls; s.x[0]=t->env;
    void *(*local)(void *,void *)=(void *(*)(void *,void *))j->env_fns[25];
    if (!target || !jni_ref_put(j,t,local(env,target),false,&s.x[1])) { why="receiver"; goto out; }
    for (int i=0;i<nargs;i++) { char k=shorty[1+i]; uint64_t v;
        if (k=='F' || k=='D') { v=k=='F'?(uint32_t)args[i].i:(uint64_t)args[i].j;
            if (nf<8) { s.v[nf][0]=v; s.v[nf][1]=0; nf++; } else stk[ns++]=v; continue; }
        switch (k) {
        case 'Z': v=args[i].z; break; case 'B': v=(uint64_t)(int64_t)args[i].b; break; case 'C': v=args[i].c; break;
        case 'S': v=(uint64_t)(int64_t)args[i].s; break; case 'I': v=(uint64_t)(int64_t)args[i].i; break; case 'J': v=(uint64_t)args[i].j; break;
        case 'L': if (args[i].l) { if (!jni_ref_put(j,t,local(env,args[i].l),false,&v)) { why="reference table full"; goto out; } } else v=0; break;
        default: why="unsupported argument kind"; goto out;
        }
        if (ng<8) s.x[ng++]=v; else stk[ns++]=v;
    }
    /* AAPCS64 (Linux): each stack argument in its own 8-byte slot at SP. */
    sp=(sp-(uint64_t)ns*8)&~UINT64_C(15); s.sp=sp;
    if (ns && !bb_write(j->engine,sp,stk,(size_t)ns*8)) { why="guest stack"; goto out; }
    ++j->native_calls; ++t->native_calls;
    entry=s;
    t->native_gate=oop_domain_call(j->domain,(uintptr_t)fn,ns?OOP_ABI_STACK_ARGS:nf?OOP_ABI_FP_SIMD:OOP_ABI_INTEGER_0_TO_8,&s,j->budget,&t->native_guest);
    t->native_state=s;
    pthread_mutex_lock(&j->lock); j->native_gate=t->native_gate; j->native_guest=t->native_guest; j->native_state=s; pthread_mutex_unlock(&j->lock);
    if (t->native_gate!=OOP_GATE_OK) goto out;
    switch (shorty[0]) {
    case 'V': break;
    case 'Z': ret->z=(uint8_t)s.x[0]; break; case 'B': ret->i=(int8_t)s.x[0]; break; case 'C': ret->i=(uint16_t)s.x[0]; break;
    case 'S': ret->i=(int16_t)s.x[0]; break; case 'I': ret->i=(int32_t)s.x[0]; break; case 'J': ret->j=(int64_t)s.x[0]; break;
    case 'F': ret->i=(int32_t)(uint32_t)s.v[0][0]; break; case 'D': ret->j=(int64_t)s.v[0][0]; break;
    case 'L': { void *host; if (!jni_ref_lookup(j,t,s.x[0],&host)) { why="returned an invalid reference"; goto out; }
        ret->l=host?tl_jni_ref(host):NULL; break; }
    default: why="unsupported return kind"; goto out;
    }
    ok=true;
out:
    /* The native frame's local references end with it, as in ART. */
    jni_release_frame(j,t,frame); t->frame=frame-1;   /* also closes frames the native left pushed */
    pthread_mutex_lock(&j->lock);
    for (size_t i=0;i<j->native_name_count;i++) if (j->native_names[i].pc==(uintptr_t)fn) {
        ++j->native_names[i].calls; if (ok) ++j->native_names[i].ok;
        else { if (!j->native_names[i].failed) { j->native_names[i].first_call=j->native_names[i].calls; j->native_names[i].first_gate=t->native_gate;
                   j->native_names[i].first_guest=t->native_guest; j->native_names[i].first_stop=t->native_state; j->native_names[i].first_entry=entry; }
               ++j->native_names[i].failed; j->native_names[i].gate=t->native_gate; j->native_names[i].guest=t->native_guest;
               j->native_names[i].stop=t->native_state; snprintf(j->native_names[i].why,sizeof(j->native_names[i].why),"%s",why); }
        /* After a native's first stop, its later calls at 1, 2, 4, ... calls on (bounded):
         * whether the guest still completes them, apart from the host frame loop. */
        if (j->native_names[i].failed) { unsigned since=j->native_names[i].calls-j->native_names[i].first_call;
            if (since && !(since&(since-1)) && since<=4096) { after=true; after_calls=j->native_names[i].calls;
                after_ok=j->native_names[i].ok; after_failed=j->native_names[i].failed; } }
        break; }
    pthread_mutex_unlock(&j->lock);
    if (after) { void tl_log_line(const char *, ...);
        tl_log_line("oop: native %s since its first stop: %u calls, %u completed in the guest, %u stopped",name,after_calls,after_ok,after_failed); }
    return ok || jni_foreign_fail(j,t,name,why);
}
static bool jni_getenv_gate(const bb_state *s, uint64_t *result, void *opaque) {
    jni_gate *j=opaque; int32_t ver=(int32_t)s->x[2]; jni_thread *t=jni_self(j);
    if (!t || !result || s->tpidr_el0!=t->tls || s->x[0]!=j->vm || !s->x[1] || !bb_access(j->engine,s->x[1],8,BB_W) ||
        (ver!=0x10001 && ver!=0x10002 && ver!=0x10004 && ver!=0x10006)) return false;
    void *actual=NULL; int32_t rc=j->getenv_fn(j->host_vm,&actual,ver);
    /* The answer must be this thread's own Husk env, given back as this
     * thread's own guest view. */
    if (!rc && (actual!=jni_host_env(j) || !bb_write(j->engine,s->x[1],&t->env,8))) return false;
    *result=(uint32_t)rc; ++j->get_env_calls; return true;
}
/* AttachCurrentThread{,AsDaemon}: a thread running guest code already has
 * guest state (it was provisioned on entry), so this yields its own env. */
static bool jni_attach_gate(const bb_state *s, uint64_t *result, void *opaque, unsigned slot) {
    jni_gate *j=opaque; jni_thread *t=jni_self(j);
    if (!t || !result || s->tpidr_el0!=t->tls || s->x[0]!=j->vm ||
        !s->x[1] || !bb_access(j->engine,s->x[1],8,BB_W) || s->x[2]) return false;
    const void *const *vm_fns=*(const void *const *const *)j->host_vm;
    int32_t (*fn)(void *,void **,void *)=(int32_t (*)(void *,void **,void *))vm_fns[slot];
    void *actual=NULL; int32_t rc=fn ? fn(j->host_vm,&actual,NULL) : -1;
    if (!rc && (actual!=jni_host_env(j) || !bb_write(j->engine,s->x[1],&t->env,8))) return false;
    *result=(uint32_t)rc; ++j->attach_calls; return true;
}
static bool jni_attach4_gate(const bb_state *s, uint64_t *r, void *p) { return jni_attach_gate(s,r,p,4); }
static bool jni_attach7_gate(const bb_state *s, uint64_t *r, void *p) { return jni_attach_gate(s,r,p,7); }
static bool jni_gate_open(jni_gate *j, bb_engine *engine, oop_domain *domain, uint64_t tls) {
    if (!j || !engine || !domain || !tls) return false;
    memset(j,0,sizeof(*j));
    j->engine=engine; j->domain=domain; j->thread=pthread_self(); j->tls=tls; j->free_ref=-1;
    j->host_vm=tl_jni_vm(); void *host_env=tl_jni_env();
    if (!j->host_vm || !host_env) return false;
    const void *const *vm_fns=*(const void *const *const *)j->host_vm;
    const void *const *env_fns=*(const void *const *const *)host_env;
    if (!vm_fns || !env_fns || !vm_fns[6] || !env_fns[6] || !env_fns[21] || !env_fns[22] || !env_fns[23] || !env_fns[31] || !env_fns[33] || !env_fns[36] || !env_fns[113] || !env_fns[167] || !env_fns[15] || !env_fns[17] || !env_fns[25] || !env_fns[169] || !env_fns[170]) return false;
    j->env_fns=env_fns;
    j->getenv_fn=(int32_t (*)(void *,void **,int32_t))vm_fns[6];
    if (pthread_mutex_init(&j->lock,NULL)) return false;
    if (pthread_key_create(&j->key,jni_thread_exit)) { pthread_mutex_destroy(&j->lock); return false; }
    j->key_ok=true;
    j->refs=calloc(JNI_REF_LIMIT,sizeof(*j->refs));
    j->allocation=j->refs?bb_heap_malloc(engine,96+233*8):0;
    if (!j->allocation) goto fail;
    j->vm=j->allocation; j->vm_table=j->allocation+16; j->env=j->allocation+80; j->env_table=j->allocation+96;
    uint64_t vm_table[8]={0}, env_table[233]={0};
    for (size_t i=3;i<8;i++) if (vm_fns[i]) vm_table[i]=JNI_VM_TOKEN_BASE+i*4;
    for (size_t i=4;i<233;i++) if (env_fns[i]) env_table[i]=JNI_ENV_TOKEN_BASE+i*4;
    if (!bb_write(engine,j->vm,&j->vm_table,8) || !bb_write(engine,j->env,&j->env_table,8) ||
        !bb_write(engine,j->vm_table,vm_table,sizeof(vm_table)) || !bb_write(engine,j->env_table,env_table,sizeof(env_table))) goto fail;
    /* The opening thread is slot 0 and brings its own TLS (and stack, j->stack). */
    jni_thread *t=jni_slot_claim(j);
    if (!t) goto fail;
    t->env=j->env; t->tls=tls;
    if (!oop_domain_thread_attach(domain,tls) || pthread_setspecific(j->key,t)) goto fail;
    /* On registration failure the domain must be destroyed before j or its
     * allocation is released; earlier registered callbacks still reference j. */
    if (!oop_domain_register_host(domain,JNI_VM_TOKEN_BASE+6*4,jni_getenv_gate,j) ||
        (vm_fns[4] && !oop_domain_register_host(domain,JNI_VM_TOKEN_BASE+4*4,jni_attach4_gate,j)) ||
        (vm_fns[7] && !oop_domain_register_host(domain,JNI_VM_TOKEN_BASE+7*4,jni_attach7_gate,j)) ||
        !oop_domain_register_host(domain,JNI_ENV_TOKEN_BASE+6*4,jni_findclass_gate,j) ||
        !oop_domain_register_host(domain,JNI_ENV_TOKEN_BASE+31*4,jni_objectclass_gate,j) ||
        !oop_domain_register_host(domain,JNI_ENV_TOKEN_BASE+21*4,jni_globalref_gate,j) ||
        !oop_domain_register_host(domain,JNI_ENV_TOKEN_BASE+22*4,jni_deleteglobal_gate,j) ||
        !oop_domain_register_host(domain,JNI_ENV_TOKEN_BASE+23*4,jni_deletelocal_gate,j) ||
        !oop_domain_register_host(domain,JNI_ENV_TOKEN_BASE+33*4,jni_getmethod_gate,j) ||
        !oop_domain_register_host(domain,JNI_ENV_TOKEN_BASE+167*4,jni_newstringutf_gate,j) ||
        !oop_domain_register_host(domain,JNI_ENV_TOKEN_BASE+113*4,jni_getstaticmethod_gate,j) ||
        !oop_domain_register_host(domain,JNI_ENV_TOKEN_BASE+15*4,jni_exceptionoccurred_gate,j) ||
        !oop_domain_register_host(domain,JNI_ENV_TOKEN_BASE+17*4,jni_exceptionclear_gate,j) ||
        !oop_domain_register_host(domain,JNI_ENV_TOKEN_BASE+228*4,jni_exceptioncheck_gate,j) ||
        !oop_domain_register_host(domain,JNI_ENV_TOKEN_BASE+169*4,jni_getstringutfchars_gate,j) ||
        !oop_domain_register_host(domain,JNI_ENV_TOKEN_BASE+170*4,jni_releasestringutfchars_gate,j)) return false;
    /* All three forms of Call[Static]<T>Method: C variadic (slot+0), V and A;
     * float/double results return in v0. */
    if (!jni_register_ext(j)) return false;
#define JNI_CALLS(T,I) {I,jni_call_v_##T,jni_call_a_##T,jni_call_c_##T,jni_scall_v_##T,jni_scall_a_##T,jni_scall_c_##T}
    static const struct { unsigned t; oop_host_callback v,a,c,sv,sa,sc; } calls[]={
        JNI_CALLS(L,0),JNI_CALLS(Z,1),JNI_CALLS(B,2),JNI_CALLS(C,3),JNI_CALLS(S,4),
        JNI_CALLS(I,5),JNI_CALLS(J,6),JNI_CALLS(F,7),JNI_CALLS(D,8),JNI_CALLS(V,9)};
#undef JNI_CALLS
    for (size_t i=0;i<sizeof(calls)/sizeof(calls[0]);i++) {
        uint64_t inst=34+calls[i].t*3, stat=114+calls[i].t*3;
        if (!env_fns[inst+2] || !env_fns[stat+2] ||
            !oop_domain_register_host(domain,JNI_ENV_TOKEN_BASE+inst*4,calls[i].c,j) ||
            !oop_domain_register_host(domain,JNI_ENV_TOKEN_BASE+stat*4,calls[i].sc,j) ||
            !oop_domain_register_host(domain,JNI_ENV_TOKEN_BASE+(inst+1)*4,calls[i].v,j) ||
            !oop_domain_register_host(domain,JNI_ENV_TOKEN_BASE+(inst+2)*4,calls[i].a,j) ||
            !oop_domain_register_host(domain,JNI_ENV_TOKEN_BASE+(stat+1)*4,calls[i].sv,j) ||
            !oop_domain_register_host(domain,JNI_ENV_TOKEN_BASE+(stat+2)*4,calls[i].sa,j)) return false;
    }
    return true;
fail:
    if (j->allocation) bb_heap_free(engine,j->allocation);
    if (j->key_ok) { pthread_setspecific(j->key,NULL); pthread_key_delete(j->key); }
    pthread_mutex_destroy(&j->lock); free(j->refs); memset(j,0,sizeof(*j)); return false;
}
/* Call only after destroying the domain and joining every other thread that
 * entered, so no registered callback or thread record still references this
 * bridge. Releases actual Husk references, then guest storage. */
static bool jni_gate_close(jni_gate *j) {
    if (!j || !j->allocation || !pthread_equal(j->thread,pthread_self())) return false;
    void *env=jni_host_env(j); if (!env) return false;
    pthread_key_delete(j->key); j->key_ok=false;   /* no thread-exit destructor runs after this */
    for (size_t i=0;i<j->ref_count;i++) if (j->refs[i].live) {
        void (*fn)(void *,void *)=(void (*)(void *,void *))j->env_fns[j->refs[i].global?22:23];
        fn(env,j->refs[i].host); j->refs[i].live=false; j->refs[i].host=NULL;
    }
    for (size_t i=0;i<JNI_UTF_LIMIT;i++) if (j->utf[i].guest) {
        void (*rel)(void *,void *,const char *)=(void (*)(void *,void *,const char *))j->env_fns[170];
        rel(env,j->utf[i].string,j->utf[i].host); bb_heap_free(j->engine,j->utf[i].guest);
    }
    for (size_t i=0;i<JNI_UTF_LIMIT;i++) if (j->elems[i].guest) {
        ((void (*)(void *,void *,const void *,int32_t))j->env_fns[191+j->elems[i].kind])(env,j->elems[i].array,j->elems[i].host,2);
        bb_heap_free(j->engine,j->elems[i].guest);
    }
    for (unsigned i=0;i<JNI_THREAD_LIMIT;i++) if (j->threads[i].used && j->threads[i].provisioned) {
        jni_thread *t=&j->threads[i];
        if (t->stack_alloc) bb_heap_free(j->engine,t->stack_alloc);
        if (t->tls_alloc) bb_heap_free(j->engine,t->tls_alloc);
        if (t->env_alloc) bb_heap_free(j->engine,t->env_alloc);
    }
    if (!bb_heap_free(j->engine,j->allocation)) return false;
    pthread_mutex_destroy(&j->lock); free(j->refs); memset(j,0,sizeof(*j)); return true;
}
/* The calling thread's locals (all frames). Globals and other threads' locals stay. */
static bool jni_gate_release_locals(jni_gate *j) {
    jni_thread *t=jni_self(j);
    if (!t || !j->allocation) return false;
    jni_release_frame(j,t,0); return true;
}
#endif
