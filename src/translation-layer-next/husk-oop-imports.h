/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Reusable out-of-place import bridge. One place that registers host-call gates
 * for the ordinary native imports a guest ARM64 library reaches (libc/bionic,
 * later pthread/math/GL), each with a typed signature and checked guest-memory
 * access, reusing Husk's real bionic implementations (tl_bionic_find). The
 * research runners register these through the bridge instead of keeping private
 * copies, so the same adapters serve the production OOP launch.
 *
 * Only the opt-in diagnostic / domain-test builds contain it.
 */
#pragma once
#if defined(HUSK_OOP_IOS_DIAG) || defined(HUSK_OOP_DOMAIN_TEST)
#include "../../research/arm64-oop/block_engine.h"
#include "husk-oop-domain.h"

typedef struct oop_imports oop_imports;

/* A bridge over one engine+domain. The domain's gates are registered into the
 * engine; the bridge keeps per-import call counts for diagnostics. */
oop_imports *oop_imports_create(bb_engine *engine, oop_domain *domain);
void oop_imports_destroy(oop_imports *b);

/* Register the stateless memory and string family (memcpy, memmove, memset,
 * memcmp, strlen, strcmp, strncmp, strnlen, and the fortify __*_chk guards),
 * resolving each from Husk's bionic. Returns the number of host gates
 * registered, or -1 on a hard error (bad arguments, out of gate slots). An
 * import whose host symbol is absent is skipped, not an error. */
int oop_imports_register_mem(oop_imports *b);

/* Register the GLES 2.0 family (68 entry points) resolved through Husk's
 * EGL/ANGLE resolver. Calls run on, and use the GL context current on, the
 * calling thread. Returns gates registered, 0 without a GLES library, -1 on a
 * hard error. */
int oop_imports_register_gl(oop_imports *b);
/* Register libc strings (copy/concat/search/compare/dup/convert, fortify
 * variants enforcing their bound), libm float/double functions and the time
 * calls, from Husk's bionic. Same return convention as above. */
int oop_imports_register_libc(oop_imports *b);
/* snprintf/sprintf/vsnprintf/vsprintf (and fortify variants), vasprintf and
 * __android_log_print, through a guest-varargs formatter. */
int oop_imports_register_printf(oop_imports *b);
/* Husk's bionic stdio and fd calls (fopen..fclose, fread/fwrite, seek/tell,
 * open/read/write/close, stat/fstat/access, remove/rename). FILE* values are
 * opaque handles: the standard streams and those returned here. */
int oop_imports_register_files(oop_imports *b);
unsigned oop_imports_calls_named(const oop_imports *b, const char *name);
/* Sockets over Husk's Android-speaking bionic socket layer: socket..close,
 * send/recv(from/to), poll/select, fcntl/ioctl (integer forms), getaddrinfo
 * (copied into the guest heap), inet_*, getnameinfo. */
int oop_imports_register_net(oop_imports *b);
/* Guest raw system calls (SVC #0), as the in-place backend's Linux layer
 * serves them; process_vm_readv reads guest memory. Unknown calls stop. */
int oop_imports_register_syscalls(oop_imports *b);
unsigned oop_imports_syscall_count(long nr);
/* The generic runtime family: guest heap (malloc/calloc/realloc/free, any
 * attached thread), pthread mutex/cond objects, syscall(gettid), arc4random,
 * sigfillset/sigdelset, getenv, strtoul, wcrtomb. */
int oop_imports_register_runtime(oop_imports *b);
/* setjmp/sigsetjmp/longjmp/siglongjmp on guest state (oop_domain_register_setjmp). */
int oop_imports_register_setjmp(oop_imports *b);
/* Rebind the image's host-bound data imports that the guest reads itself
 * (today: __stack_chk_guard, by value) to guest copies. Call after the heap
 * exists and before any guest code runs. Returns rebound count or -1. */
int oop_imports_bind_data(oop_imports *b, unsigned *left_host_bound);
/* __errno: each guest thread's errno is the word at TPIDR_EL0 + tls_offset,
 * synchronized with Husk's guest errno around every host call. */
#define OOP_IMPORTS_ERRNO_TLS_OFFSET 0xf00u
int oop_imports_register_errno(oop_imports *b, uint64_t tls_offset);
/* The most recent refused GL call and why (diagnostics; NULL if none). */
const char *oop_imports_refusal(oop_imports *b);

/* Total successful host calls through this bridge, and the name/count of the
 * most recently called import (diagnostics; NULL name if none yet). */
unsigned oop_imports_calls(const oop_imports *b);
const char *oop_imports_last(const oop_imports *b);
size_t oop_imports_count(const oop_imports *b);
#endif
