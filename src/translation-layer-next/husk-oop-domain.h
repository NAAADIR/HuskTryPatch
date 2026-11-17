/* SPDX-License-Identifier: GPL-2.0-or-later */
#pragma once
#include "../../research/arm64-oop/block_engine.h"
#include "husk-tl-ld.h"

/* Controlled, serialized integer-only domain. This is not a general JNI ABI. */
typedef struct oop_domain oop_domain;
typedef enum { OOP_GATE_OK, OOP_GATE_ARGUMENT, OOP_GATE_UNREGISTERED,
               OOP_GATE_ABI_UNSUPPORTED, OOP_GATE_GUEST_ERROR, OOP_GATE_ABI_VIOLATION,
               OOP_GATE_UNKNOWN_TARGET } oop_gate_result;
typedef enum { OOP_ABI_INTEGER_0_TO_8, OOP_ABI_FP_SIMD, OOP_ABI_STACK_ARGS } oop_abi;
typedef bool (*oop_host_callback)(const bb_state *state, uint64_t *result, void *opaque);
oop_domain *oop_domain_create(bb_engine *engine);
/* Turn on multithread entry, once, after all host gates are registered and
 * before any second thread enters. Guest instruction execution is serialized
 * per engine; host gate callbacks (where guest synchronization blocks) run
 * concurrently. Call-stack state is tracked per entering thread. */
bool oop_domain_enable_threads(oop_domain *domain);
void oop_domain_destroy(oop_domain *domain);
bool oop_domain_register_entry(oop_domain *domain, uint64_t guest_pc);
bool oop_domain_register_host(oop_domain *domain, uint64_t token, oop_host_callback callback, void *opaque);
/* State supplies all registers, 16-byte aligned writable guest SP and guest TLS.
 * x0-x7 are integer arguments. PC and LR are set by the gate; all final guest
 * state is returned, including on guest error. No implicit OS TLS is installed. */
oop_gate_result oop_domain_call(oop_domain *domain, uint64_t guest_pc, oop_abi abi,
                                bb_state *state, size_t budget, bb_result *guest_result);
/* While a host callback runs (a guest call is suspended in it), the highest
 * 16-byte-aligned guest SP a nested oop_domain_call may use, below the
 * suspended frame. False when no guest call is suspended. */
bool oop_domain_reentry_stack(const oop_domain *domain, uint64_t *sp);
/* errno coherence: each guest thread's errno is the 32-bit word at its
 * TPIDR_EL0 + tls_offset (inside its guest TLS block, clear of the bionic
 * slots). Around every host callback the domain copies it into Husk's
 * per-host-thread guest errno and back. Set before enabling threads. */
bool oop_domain_set_errno(oop_domain *domain, int *(*host_errno)(void), uint64_t tls_offset);
/* qsort/bsearch with a guest comparator (nested guest calls). */
bool oop_domain_register_sort(oop_domain *domain, uint64_t qsort_fn, uint64_t bsearch_fn);
/* pthread_once with a guest init routine (bionic's int states 0/1/2 in guest memory). */
bool oop_domain_register_once(oop_domain *domain, uint64_t pthread_once_fn);
/* setjmp/sigsetjmp and longjmp/siglongjmp on guest state (host addresses of
 * the imports; 0 skips one). longjmp is honoured only within one guest call. */
bool oop_domain_register_setjmp(oop_domain *domain, uint64_t setjmp_fn, uint64_t sigsetjmp_fn, uint64_t longjmp_fn, uint64_t siglongjmp_fn);
/* From inside a host callback: set the guest's v0 (low 64 bits; the rest is
 * cleared) for a float/double result. x0 is still the callback's result. */
bool oop_domain_return_fp(oop_domain *domain, uint64_t bits);
/* Guest thread identity. A host thread that will run guest code declares the
 * guest TLS block (TPIDR_EL0) it enters with; host gates that keep per-thread
 * or thread-confined state ask oop_domain_thread_owns instead of comparing
 * against one fixed thread. One TLS per host thread; re-attaching with the
 * same TLS is idempotent, a different TLS is refused until detached. The
 * per-thread record is freed at host-thread exit. */
bool oop_domain_thread_attach(oop_domain *domain, uint64_t tls);
void oop_domain_thread_detach(oop_domain *domain);
bool oop_domain_thread_owns(oop_domain *domain, uint64_t tls);
/* Number of host threads currently attached (diagnostics). */
unsigned oop_domain_thread_count(oop_domain *domain);
/* Adapter for tl_ld_init_routed. The caller must supply a coherent guest
 * stack, TLS block, and guest-resident argv/envp, and serialize the domain.
 * Unsupported calls stop initialization; prior constructor writes remain. */
typedef struct {
    oop_domain *domain;
    uint64_t stack, tls, argv, envp;
    size_t budget;
    oop_gate_result gate_result;
    bb_result guest_result;
    bb_state last_state; /* final guest state, including the stopping PC */
} oop_init_context;
bool oop_domain_init_gate(tl_lib *owner, uintptr_t entry, int argc,
                          char **argv, char **envp, void *opaque);
#ifdef BB_TESTING
void oop_domain_test_reference(oop_domain *domain, bool enabled);
#endif
