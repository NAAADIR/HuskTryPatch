/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Isolated locale gate. Handles are the same opaque locale_t values used by
 * Husk's bionic locale shims. uselocale state is per host thread, as in
 * bionic. With `domain` set, any thread attached to it may call; the shared
 * handle list is then locked. */
#ifndef HUSK_RESEARCH_LOCALE_GATE_H
#define HUSK_RESEARCH_LOCALE_GATE_H
#include <locale.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include "husk-oop-domain.h"

typedef struct {
    pthread_t thread;
    uint64_t guest_tls;
    locale_t (*use)(locale_t);
    locale_t handles[64];
    size_t count;
    oop_domain *domain;
    pthread_mutex_t lock;
} locale_gate;

static bool locale_gate_init(locale_gate *g, uint64_t tls, locale_t (*use)(locale_t)) {
    if (!g || !tls || !use || use((locale_t)0)!=LC_GLOBAL_LOCALE) return false;
    *g=(locale_gate){.thread=pthread_self(),.guest_tls=tls,.use=use};
    return !pthread_mutex_init(&g->lock,NULL);
}
static bool locale_gate_thread(const locale_gate *g, uint64_t tls) {
    if (g && g->domain) return oop_domain_thread_owns(g->domain,tls);
    return g && tls==g->guest_tls && pthread_equal(g->thread,pthread_self());
}
static bool locale_gate_known(locale_gate *g, locale_t l) {
    if (l==LC_GLOBAL_LOCALE) return true;
    pthread_mutex_lock(&g->lock); bool found=false;
    for (size_t i=0;i<g->count && !found;i++) found=g->handles[i]==l;
    pthread_mutex_unlock(&g->lock); return found;
}
static bool locale_gate_record(locale_gate *g, uint64_t tls, locale_t l) {
    if (!locale_gate_thread(g,tls) || !l || l==LC_GLOBAL_LOCALE) return false;
    if (locale_gate_known(g,l)) return true;
    pthread_mutex_lock(&g->lock);
    bool ok=g->count<sizeof(g->handles)/sizeof(g->handles[0]); if (ok) g->handles[g->count++]=l;
    pthread_mutex_unlock(&g->lock); return ok;
}
static bool locale_gate_use(locale_gate *g, uint64_t tls, uint64_t guest, uint64_t *result) {
    if (!result || !locale_gate_thread(g,tls)) return false;
    locale_t current=g->use((locale_t)0);
    if (!current || !locale_gate_known(g,current)) return false;
    locale_t requested=(locale_t)(uintptr_t)guest;
    if (requested && !locale_gate_known(g,requested)) return false;
    locale_t previous=g->use(requested);
    if (previous && !locale_gate_known(g,previous)) return false;
    *result=(uintptr_t)previous;
    return true;
}
#endif
