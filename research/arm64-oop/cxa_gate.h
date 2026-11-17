/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Serialized, domain-owned guest C++ destructor lifecycle for the runner. */
#ifndef HUSK_OOP_CXA_GATE_H
#define HUSK_OOP_CXA_GATE_H
#include "husk-oop-domain.h"
#include <stdlib.h>
#include <pthread.h>
typedef struct { uint64_t fn, arg, dso; bool pending; } cxa_entry;
typedef struct {
    oop_domain *domain; bb_engine *engine; pthread_t thread;
    uint64_t tls, stack; size_t budget;
    cxa_entry *entries; size_t count, capacity;
    unsigned registered, invoked, completed, depth;
    bool failed, closing;
    /* After threads are enabled: any domain-attached thread may register (a
     * function-local static's destructor is registered by whichever thread
     * first runs it). Finalization stays on the owning thread. */
    bool any_thread_register;
    oop_gate_result gate_result; bb_result guest_result; bb_state last_state;
} cxa_gate;
static bool cxa_thread(cxa_gate *c, uint64_t tls) {
    return c && !c->failed && !c->closing && tls==c->tls && pthread_equal(c->thread,pthread_self());
}
static pthread_mutex_t cxa_register_lock=PTHREAD_MUTEX_INITIALIZER;
static bool cxa_register_thread(cxa_gate *c, uint64_t tls) {
    if (c && c->any_thread_register) return !c->failed && !c->closing && oop_domain_thread_owns(c->domain,tls);
    return cxa_thread(c,tls);
}
static bool cxa_register_locked(cxa_gate *c, const bb_state *s, uint64_t *result);
static bool cxa_register(cxa_gate *c, const bb_state *s, uint64_t *result) {
    pthread_mutex_lock(&cxa_register_lock); bool ok=cxa_register_locked(c,s,result); pthread_mutex_unlock(&cxa_register_lock); return ok;
}
static bool cxa_register_locked(cxa_gate *c, const bb_state *s, uint64_t *result) {
    if (!result || !cxa_register_thread(c,s->tpidr_el0) || c->closing || !s->x[0] ||
        (s->x[0]&3) || !bb_access(c->engine,s->x[0],4,BB_X) ||
        (s->x[1] && !bb_access(c->engine,s->x[1],1,BB_R)) ||
        (s->x[2] && !bb_access(c->engine,s->x[2],1,BB_R))) return false;
    if (c->count==c->capacity) {
        size_t cap=c->capacity?c->capacity*2:16;
        if (cap>65536) { *result=UINT32_MAX; return true; }
        cxa_entry *p=realloc(c->entries,cap*sizeof(*p));
        if (!p) { *result=UINT32_MAX; return true; }
        c->entries=p; c->capacity=cap;
    }
    if (!oop_domain_register_entry(c->domain,s->x[0])) return false;
    c->entries[c->count++]=(cxa_entry){s->x[0],s->x[1],s->x[2],true};
    ++c->registered; *result=0; return true;
}
static bool cxa_finalize_state(cxa_gate *c, uint64_t dso, uint64_t stack, uint64_t tls, const bb_state *parent) {
    if (!cxa_thread(c,tls) || c->depth>=16 || (stack&15) || stack<16 ||
        !bb_access(c->engine,stack-16,16,BB_R|BB_W)) return false;
    ++c->depth;
    size_t remaining=65536;
    for (;;) {
        size_t i=c->count;
        while (i && (!c->entries[i-1].pending || (dso && c->entries[i-1].dso!=dso))) --i;
        if (!i) break;
        if (!remaining--) { c->failed=true; break; }
        cxa_entry ent=c->entries[i-1]; c->entries[i-1].pending=false;
        bb_state s=parent?*parent:(bb_state){0}; s.sp=stack; s.tpidr_el0=tls; s.x[0]=ent.arg;
        ++c->invoked;
        c->gate_result=oop_domain_call(c->domain,ent.fn,OOP_ABI_INTEGER_0_TO_8,&s,c->budget,&c->guest_result);
        c->last_state=s;
        if (c->gate_result!=OOP_GATE_OK) { c->failed=true; break; }
        ++c->completed;
    }
    --c->depth; return !c->failed;
}
static bool cxa_finalize(cxa_gate *c, uint64_t dso, uint64_t stack, uint64_t tls) {
    return cxa_finalize_state(c,dso,stack,tls,NULL);
}
static bool cxa_register_host(const bb_state *s, uint64_t *result, void *opaque) {
    return cxa_register(opaque,s,result);
}
static bool cxa_finalize_host(const bb_state *s, uint64_t *result, void *opaque) {
    if (s->sp<16 || !cxa_finalize_state(opaque,s->x[0],s->sp-16,s->tpidr_el0,s)) return false;
    *result=0; return true;
}
static bool cxa_close(cxa_gate *c) {
    if (!c || c->depth || c->closing || c->failed) return false;
    /* A destructor may register another destructor, so close only after draining. */
    if (!cxa_finalize(c,0,c->stack,c->tls)) return false;
    c->closing=true; free(c->entries); c->entries=NULL; c->count=c->capacity=0; return true;
}
#endif
