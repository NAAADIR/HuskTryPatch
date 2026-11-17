/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Thread-bound mask support for the serialized OOP runner. This does not
 * install guest handlers or claim to implement guest signal delivery. Linux
 * mask bits with no Darwin counterpart are retained in guest state; this
 * gate is only usable while those signals cannot be delivered to the domain. */
#ifndef HUSK_OOP_SIGNAL_MASK_GATE_H
#define HUSK_OOP_SIGNAL_MASK_GATE_H
#include "block_engine.h"
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
int tl_signal_to_darwin(int);
int tl_errno_to_guest(int);
void tl_set_guest_errno(int);
typedef struct {
    bb_engine *engine; pthread_t thread; uint64_t tls, mask;
    sigset_t original; bool active; unsigned calls;
} signal_mask_gate;
static bool signal_mask_open(signal_mask_gate *g, bb_engine *e, uint64_t tls) {
    if (!g || !e || !tls) return false;
    signal_mask_gate init={.engine=e,.thread=pthread_self(),.tls=tls};
    if (pthread_sigmask(SIG_SETMASK,NULL,&init.original)) return false;
    for (int i=1;i<32;i++) {
        int host=tl_signal_to_darwin(i);
        if (host>0) { int member=sigismember(&init.original,host); if (member<0) return false;
            if (member==1) init.mask|=UINT64_C(1)<<(i-1); }
    }
    init.mask&=~((UINT64_C(1)<<8)|(UINT64_C(1)<<18));
    init.active=true; *g=init; return true;
}
static bool signal_mask_call(const bb_state *s, uint64_t *result, void *opaque) {
    signal_mask_gate *g=opaque; uint64_t set=0, old; void *out=NULL;
    if (!g || !result || !g->active || s->tpidr_el0!=g->tls || !pthread_equal(g->thread,pthread_self())) return false;
    if (s->x[1] && !bb_read(g->engine,s->x[1],&set,8)) return false;
    if (s->x[2] && !bb_host_data_alias(g->engine,s->x[2],8,&out)) return false;
    old=g->mask;
    if (s->x[1]) {
        unsigned how=(unsigned)s->x[0];
        if (how>2) { tl_set_guest_errno(22); *result=UINT32_MAX; ++g->calls; return true; }
        uint64_t next=how==0 ? old|set : how==1 ? old&~set : set;
        next&=~((UINT64_C(1)<<8)|(UINT64_C(1)<<18)); /* SIGKILL/SIGSTOP */
        sigset_t actual; int rc=pthread_sigmask(SIG_SETMASK,NULL,&actual);
        if (rc) { tl_set_guest_errno(tl_errno_to_guest(rc)); *result=UINT32_MAX; ++g->calls; return true; }
        for (int i=1;i<32;i++) {
            int host=tl_signal_to_darwin(i);
            if (host<=0 || i==9 || i==19) continue;
            int r=(next&(UINT64_C(1)<<(i-1))) ? sigaddset(&actual,host) : sigdelset(&actual,host);
            if (r) return false;
        }
        rc=pthread_sigmask(SIG_SETMASK,&actual,NULL);
        if (rc) { tl_set_guest_errno(tl_errno_to_guest(rc)); *result=UINT32_MAX; ++g->calls; return true; }
        g->mask=next;
    }
    if (out) __builtin_memcpy(out,&old,8);
    *result=0; ++g->calls; return true;
}
static bool signal_mask_close(signal_mask_gate *g) {
    if (!g || !g->active || !pthread_equal(g->thread,pthread_self())) return false;
    if (pthread_sigmask(SIG_SETMASK,&g->original,NULL)) return false;
    g->active=false; return true;
}
#endif
