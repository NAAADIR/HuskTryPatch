/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Production out-of-place launch of Brave Frontier V20: see husk-oop-launch.h. */
#ifdef HUSK_OOP_IOS_DIAG
#include "husk-oop-launch.h"
#include "husk-oop-domain.h"
#include "husk-oop-imports.h"
#include "husk-tl-egl.h"
#include "husk-tl-internal.h"
#include "husk-tl-jni.h"
#include "husk-tl-dvm.h"
#include "husk-tl-ld.h"
#include "husk-tl-xmem.h"
#include "../../research/arm64-oop/block_engine.h"
#include "../../research/arm64-oop/jni_gate.h"
#include "../../research/arm64-oop/locale_gate.h"
#include "../../research/arm64-oop/cxa_gate.h"
#include "../../research/arm64-oop/signal_mask_gate.h"
#include <locale.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <wchar.h>

bool tl_ld_oop_real_open(const uint8_t *,size_t,const uint8_t *,size_t,tl_lib **,tl_lib **,unsigned *,unsigned *);
bool tl_ld_oop_test_views(tl_lib *,uint8_t **,uint8_t **,size_t *);
bool tl_ld_oop_test_tcb(tl_lib *,uint8_t **,uint8_t **);
int husk_oop_real_apk_matches(const char *path);
bool husk_oop_claim_xmem(void);
void tl_log_line(const char *fmt, ...);
void *tl_bionic_find(const char *name);

/* V20 layout, the same constants the verified runners use: libgame's code
 * PT_LOAD ends before 0x26cb000 and its data starts on 0x26cc000; libc++'s
 * code, read-only and data segments. */
#define GAME_CODE_END 0x26cb000u
#define GAME_DATA 0x26cc000u
#define CPP_CODE_END 0xd8000u
#define CPP_RO_END 0xe1000u
#define GUEST_STACK_BYTES (1u<<20)
#define CACHE_BYTES (64u<<10)
#define CACHE_SLOTS 64

/* newlocale/uselocale/mbtowc/__ctype_get_mb_cur_max over the locale gate. */
typedef struct { bb_engine *engine; locale_t (*fn)(int,const char *,locale_t); locale_gate gate; } lo_adapter;
typedef struct { locale_gate *gate; int (*fn)(wchar_t *,const char *,size_t); } mbtowc_adapter;
typedef struct { locale_gate *gate; int (*fn)(void); } mbmax_adapter;
static bool call_newlocale(const bb_state *s, uint64_t *result, void *opaque) {
    lo_adapter *l=opaque; uint64_t p=s->x[1]; unsigned char ch;
    /* A locale made from a guest string and no base; the host locale stays opaque. */
    if (s->x[2] || !locale_gate_thread(&l->gate,s->tpidr_el0)) return false;
    for (size_t n=0;n<4096;n++) {
        if (p>UINT64_MAX-n || !bb_read(l->engine,p+n,&ch,1)) return false;
        if (!ch) {
            locale_t created=l->fn((int)s->x[0],(const char *)(uintptr_t)p,(locale_t)0);
            if (created && !locale_gate_record(&l->gate,s->tpidr_el0,created)) return false;
            *result=(uintptr_t)created; return true;
        }
    }
    return false;
}
static bool call_uselocale(const bb_state *s, uint64_t *result, void *opaque) {
    lo_adapter *l=opaque; return locale_gate_use(&l->gate,s->tpidr_el0,s->x[0],result);
}
static bool call_mbtowc(const bb_state *s, uint64_t *result, void *opaque) {
    mbtowc_adapter *m=opaque;
    if (!locale_gate_thread(m->gate,s->tpidr_el0) || s->x[0] || s->x[1]) return false;   /* the codecvt reset query */
    *result=(uint32_t)m->fn(NULL,NULL,(size_t)s->x[2]); return true;
}
static bool call_mbmax(const bb_state *s, uint64_t *result, void *opaque) {
    mbmax_adapter *m=opaque; if (!locale_gate_thread(m->gate,s->tpidr_el0)) return false;
    *result=(uint32_t)m->fn(); return true;
}

static struct {
    pthread_mutex_t lock;
    bool prepared, loaded, failed;
    tl_lib *game, *cpp;
    uint8_t *tcb, *stack;
    size_t heap_bytes;
    bb_engine *engine; oop_domain *domain; oop_imports *imports;
    lo_adapter locale; mbtowc_adapter mb; mbmax_adapter mbmax;
    cxa_gate cxa; signal_mask_gate mask; bool mask_open;
    jni_gate jni;
    oop_init_context init;
    unsigned attempted, completed, claims;
    int onload_version;
    char failure[200];
} G = { .lock = PTHREAD_MUTEX_INITIALIZER };

/* ------------------------------------------------- guest threads
 * pthread_create starts a host thread that is provisioned like any other
 * guest thread (its own JNIEnv view, TLS block, guest stack, domain identity)
 * and runs the guest start routine. A guest pthread_t is the host pthread_t,
 * an opaque handle to the guest. pthread_exit is honoured only on threads the
 * guest created (Java threads never exit through guest code). */
typedef struct { uint64_t fn, arg; } gthread_start;
static __thread bool t_guest_created;
static _Atomic unsigned g_threads_started, g_threads_failed;
static void *guest_thread_main(void *p) {
    gthread_start st=*(gthread_start *)p; free(p);
    t_guest_created=true;
    jni_thread *t=jni_thread_provision(&G.jni);
    if (!t || !oop_domain_register_entry(G.domain,st.fn)) { ++g_threads_failed; tl_log_line("oop: guest thread %#llx: no guest state",(unsigned long long)st.fn); return NULL; }
    ++g_threads_started;
    bb_state s={0}; bb_result gr; s.sp=t->stack; s.tpidr_el0=t->tls; s.x[0]=st.arg;
    oop_gate_result g=oop_domain_call(G.domain,st.fn,OOP_ABI_INTEGER_0_TO_8,&s,SIZE_MAX,&gr);
    if (g!=OOP_GATE_OK) { ++g_threads_failed;
        const char *tl_bionic_name_of(const void *); const char *hn=tl_bionic_name_of((void *)(uintptr_t)s.pc);
        uintptr_t gb=(uintptr_t)tl_ld_lib_base(G.game);
        uint32_t w=0; bool hw=gr==BB_UNSUPPORTED && bb_read(G.engine,s.pc,&w,4);
        tl_log_line("oop: guest thread %#llx stopped: gate=%d guest=%s pc=%#llx (game+%#llx)%s%s word=%08x%s lr=game+%#llx",(unsigned long long)st.fn,g,bb_result_name(gr),
                    (unsigned long long)s.pc,(unsigned long long)(s.pc-gb),hn?" host=":"",hn?hn:"",w,hw?"":"(n/a)",(unsigned long long)(s.x[30]-gb)); }
    return (void *)(uintptr_t)s.x[0];
}
static bool gate_pthread_create(const bb_state *s, uint64_t *result, void *opaque) {
    (void)opaque; void *out; uint32_t flags=0;
    if (!G.loaded || !bb_host_data_alias(G.engine,s->x[0],8,&out) || !bb_access(G.engine,s->x[2],4,BB_X) ||
        (s->x[1] && !bb_read(G.engine,s->x[1],&flags,4))) return false;   /* bionic pthread_attr_t: flags first; bit 0 detached */
    gthread_start *st=malloc(sizeof(*st)); if (!st) { *result=11; return true; }
    st->fn=s->x[2]; st->arg=s->x[3];
    pthread_attr_t a; pthread_attr_init(&a); pthread_attr_setstacksize(&a,16u<<20);
    if (flags&1) pthread_attr_setdetachstate(&a,PTHREAD_CREATE_DETACHED);
    pthread_t h; int rc=pthread_create(&h,&a,guest_thread_main,st); pthread_attr_destroy(&a);
    if (rc) free(st); else { uint64_t v=(uintptr_t)h; memcpy(out,&v,8); }
    *result=(uint32_t)rc; return true;
}
static bool gate_pthread_join(const bb_state *s, uint64_t *result, void *opaque) {
    (void)opaque; void *out=NULL, *ret=NULL;
    if (s->x[1] && !bb_host_data_alias(G.engine,s->x[1],8,&out)) return false;
    int rc=pthread_join((pthread_t)(uintptr_t)s->x[0],&ret);
    if (!rc && out) { uint64_t v=(uintptr_t)ret; memcpy(out,&v,8); }
    *result=(uint32_t)rc; return true;
}
static bool gate_pthread_detach(const bb_state *s, uint64_t *result, void *opaque) { (void)opaque; *result=(uint32_t)pthread_detach((pthread_t)(uintptr_t)s->x[0]); return true; }
static bool gate_pthread_self(const bb_state *s, uint64_t *result, void *opaque) { (void)s; (void)opaque; *result=(uintptr_t)pthread_self(); return true; }
static bool gate_pthread_equal(const bb_state *s, uint64_t *result, void *opaque) { (void)opaque; *result=s->x[0]==s->x[1]; return true; }
static bool gate_pthread_exit(const bb_state *s, uint64_t *result, void *opaque) {
    (void)opaque; (void)result;
    if (!t_guest_created) return false;   /* a Java thread does not exit from guest code */
    pthread_exit((void *)(uintptr_t)s->x[0]);
}
static bool fail(char *err, size_t n, const char *why) {
    snprintf(G.failure,sizeof(G.failure),"%s",why);
    if (err && n) snprintf(err,n,"%s",why);
    tl_log_line("oop: launch failed: %s",why);
    return false;
}
bool husk_oop_launch_requested(void) { const char *v=getenv("HUSK_OOP_GAME"); return v && v[0]=='1'; }

bool husk_oop_launch_prepare(const char *apk, const char *egl, const char *gles, char *err, size_t errlen) {
    pthread_mutex_lock(&G.lock);
    if (G.prepared) { pthread_mutex_unlock(&G.lock); return true; }
    bool ok=false; char e[160]; tl_zip zip; bool zip_open=false;
    const uint8_t *gbytes,*cbytes; size_t gn,cn; bool gowned=false,cowned=false;
    if (!apk || !husk_oop_real_apk_matches(apk)) { fail(err,errlen,"apk_identity: not the verified Brave Frontier V20 APK"); goto out; }
    /* The JIT arena is the OOP image's, for this process (iOS: debugger-granted). */
    if (!tl_xmem_is_unused() || !husk_oop_claim_xmem()) { fail(err,errlen,"jit_arena_busy: another engine already owns it"); goto out; }
    /* The device's JIT region may be smaller than a Mac's: take the largest that opens; the heap is sized from it. */
    static const size_t sizes[]={512u<<20,384u<<20,256u<<20,192u<<20}; bool opened=false;
    for (size_t i=0;i<4 && !opened;i++) opened=tl_xmem_open(sizes[i],e,sizeof(e));
    if (!opened) { fail(err,errlen,"jit_unavailable: the JIT arena could not be opened"); goto out; }
    /* GLES imports resolve through ANGLE: it must be loaded before relocation. */
    if (!egl || !tl_egl_init(egl,gles,NULL,0)) { fail(err,errlen,"angle_unavailable"); goto out; }
    if (!tl_zip_open(&zip,apk,e,sizeof(e))) { fail(err,errlen,"apk_unreadable"); goto out; }
    zip_open=true;
    if (!tl_zip_data(&zip,tl_zip_find(&zip,"lib/arm64-v8a/libgame.so"),50u<<20,&gbytes,&gn,&gowned,e,sizeof(e)) ||
        !tl_zip_data(&zip,tl_zip_find(&zip,"lib/arm64-v8a/libc++_shared.so"),2u<<20,&cbytes,&cn,&cowned,e,sizeof(e))) { fail(err,errlen,"apk_entries"); goto out; }
    unsigned stage=0,missing=0;
    if (!tl_ld_oop_real_open(gbytes,gn,cbytes,cn,&G.game,&G.cpp,&stage,&missing)) {
        char why[120]; snprintf(why,sizeof(why),"image_map stage=%u unresolved=%u (a library or APK was registered first?)",stage,missing);
        fail(err,errlen,why); goto out; }
    if (tl_ld_find_lib("libgame.so") || tl_ld_find_lib("libc++_shared.so")) { fail(err,errlen,"image_published"); goto out; }
    uint8_t *g,*gw,*c,*cw,*tcbw,*stackw,*heap,*heapw,*cache,*cachew; size_t gs,cs;
    if (!tl_ld_oop_test_views(G.game,&g,&gw,&gs) || !tl_ld_oop_test_views(G.cpp,&c,&cw,&cs) || !tl_ld_oop_test_tcb(G.cpp,&G.tcb,&tcbw)) { fail(err,errlen,"image_views"); goto out; }
    /* One guest span: both images (either order), then stack, then heap, all in one xmem region. */
    uint8_t *lo=g<c?g:c, *low=g<c?gw:cw, *hi=g<c?c:g;
    if ((size_t)(c-lo)!=(size_t)(cw-low) || (size_t)(g-lo)!=(size_t)(gw-low)) { fail(err,errlen,"image_alias_layout"); goto out; }
    if (!tl_xmem_alloc(GUEST_STACK_BYTES,&G.stack,&stackw) || G.stack<=hi || (size_t)(G.stack-lo)!=(size_t)(stackw-low)) { fail(err,errlen,"guest_stack"); goto out; }
    size_t avail=tl_xmem_size()-tl_xmem_used(), reserve=CACHE_BYTES+(16u<<20);
    G.heap_bytes=avail>reserve?(avail-reserve)&~(size_t)16383:0;
    if (G.heap_bytes>(256u<<20)) G.heap_bytes=256u<<20;
    if (G.heap_bytes<(32u<<20) || !tl_xmem_alloc(G.heap_bytes,&heap,&heapw) || heap<=G.stack || (size_t)(heap-lo)!=(size_t)(heapw-low)) { fail(err,errlen,"guest_heap"); goto out; }
    size_t span=(size_t)(heap-lo)+G.heap_bytes;
    if (!tl_xmem_alloc(CACHE_BYTES,&cache,&cachew)) { fail(err,errlen,"code_cache"); goto out; }
    /* Only translated blocks execute: the guest's canonical view need not be executable.
     * The engine's own logical permissions govern guest access either way. */
    if (mprotect(lo,span,PROT_READ)) tl_log_line("oop: guest view stays as mapped (mprotect refused); logical permissions apply");
    G.engine=bb_attach(lo,low,span,CACHE_SLOTS,cachew,cache,CACHE_BYTES);
    if (!G.engine) { fail(err,errlen,"engine_attach"); goto out; }
    size_t go=(size_t)(g-lo), co=(size_t)(c-lo), to=(size_t)(G.tcb-lo), so=(size_t)(G.stack-lo);
    if (gs<GAME_DATA || cs<CPP_RO_END+0x3000 ||
        !bb_protect(G.engine,go,GAME_CODE_END,BB_R|BB_X) || !bb_protect(G.engine,go+GAME_DATA,gs-GAME_DATA,BB_R|BB_W) ||
        !bb_protect(G.engine,co,CPP_CODE_END,BB_R|BB_X) || !bb_protect(G.engine,co+CPP_CODE_END,CPP_RO_END-CPP_CODE_END,BB_R) ||
        !bb_protect(G.engine,co+CPP_RO_END,cs-CPP_RO_END,BB_R|BB_W) || !bb_protect(G.engine,to,16384,BB_R|BB_W) ||
        !bb_protect(G.engine,so,GUEST_STACK_BYTES,BB_R|BB_W) || !bb_heap_init(G.engine,(size_t)(heap-lo),G.heap_bytes)) { fail(err,errlen,"guest_permissions"); goto out; }
    /* The original code bytes stay what the APK has. */
    if (memcmp(g,gbytes,0x26ca520)) { fail(err,errlen,"original_code_changed"); goto out; }
    uint64_t self=(uintptr_t)G.tcb; memcpy(tcbw,&self,sizeof(self));   /* TLS_SLOT_SELF: the canonical guest view */
    uintptr_t arg=(uintptr_t)G.stack+0x300; uint64_t av[2]={arg,0}, ev=0;
    if (!bb_write(G.engine,arg,"app_process64",14) || !bb_write(G.engine,(uintptr_t)G.stack+0x200,av,sizeof(av)) ||
        !bb_write(G.engine,(uintptr_t)G.stack+0x220,&ev,sizeof(ev))) { fail(err,errlen,"guest_argv"); goto out; }
    G.domain=oop_domain_create(G.engine); G.imports=G.domain?oop_imports_create(G.engine,G.domain):NULL;
    if (!G.imports) { fail(err,errlen,"domain"); goto out; }
    unsigned host_bound=0;
    if (oop_imports_bind_data(G.imports,&host_bound)<1) { fail(err,errlen,"data_imports"); goto out; }
    if (oop_imports_register_runtime(G.imports)<14 || oop_imports_register_mem(G.imports)<4 || oop_imports_register_gl(G.imports)!=68 ||
        oop_imports_register_libc(G.imports)<40 || oop_imports_register_errno(G.imports,OOP_IMPORTS_ERRNO_TLS_OFFSET)!=1 ||
        oop_imports_register_printf(G.imports)<6 || oop_imports_register_files(G.imports)<20 || oop_imports_register_setjmp(G.imports)<2 ||
        oop_imports_register_net(G.imports)<20) {
        fail(err,errlen,"import_bridge"); goto out; }
    G.locale=(lo_adapter){.engine=G.engine,.fn=(locale_t (*)(int,const char *,locale_t))tl_bionic_find("newlocale")};
    locale_t (*use_locale)(locale_t)=(locale_t (*)(locale_t))tl_bionic_find("uselocale");
    if (!G.locale.fn || !use_locale || !locale_gate_init(&G.locale.gate,(uintptr_t)G.tcb,use_locale)) { fail(err,errlen,"locale_gate"); goto out; }
    G.locale.gate.domain=G.domain;
    G.mb=(mbtowc_adapter){.gate=&G.locale.gate,.fn=(int (*)(wchar_t *,const char *,size_t))tl_bionic_find("mbtowc")};
    G.mbmax=(mbmax_adapter){.gate=&G.locale.gate,.fn=(int (*)(void))tl_bionic_find("__ctype_get_mb_cur_max")};
    void *atexit_fn=tl_bionic_find("__cxa_atexit"), *finalize_fn=tl_bionic_find("__cxa_finalize");
    G.cxa=(cxa_gate){.domain=G.domain,.engine=G.engine,.thread=pthread_self(),.tls=(uintptr_t)G.tcb,
        .stack=(uintptr_t)G.stack+GUEST_STACK_BYTES-16,.budget=50000000,.any_thread_register=true};
    if (!G.mb.fn || !G.mbmax.fn || !atexit_fn || !finalize_fn ||
        !oop_domain_register_host(G.domain,(uintptr_t)G.locale.fn,call_newlocale,&G.locale) ||
        !oop_domain_register_host(G.domain,(uintptr_t)use_locale,call_uselocale,&G.locale) ||
        !oop_domain_register_host(G.domain,(uintptr_t)G.mb.fn,call_mbtowc,&G.mb) ||
        !oop_domain_register_host(G.domain,(uintptr_t)G.mbmax.fn,call_mbmax,&G.mbmax) ||
        !oop_domain_register_host(G.domain,(uintptr_t)atexit_fn,cxa_register_host,&G.cxa) ||
        !oop_domain_register_host(G.domain,(uintptr_t)finalize_fn,cxa_finalize_host,&G.cxa)) { fail(err,errlen,"runtime_gates"); goto out; }
    static const struct { const char *name; oop_host_callback fn; } threads[]={
        {"pthread_create",gate_pthread_create},{"pthread_join",gate_pthread_join},{"pthread_detach",gate_pthread_detach},
        {"pthread_self",gate_pthread_self},{"pthread_equal",gate_pthread_equal},{"pthread_exit",gate_pthread_exit}};
    for (size_t i=0;i<sizeof(threads)/sizeof(threads[0]);i++) { void *f=tl_bionic_find(threads[i].name);
        if (f && !oop_domain_register_host(G.domain,(uintptr_t)f,threads[i].fn,NULL)) { fail(err,errlen,"thread_gates"); goto out; } }
    /* OpenSSL's ARM capability probe would raise SIGILL in guest code: the
     * generic code path is selected the way OpenSSL documents (OPENSSL_armcap). */
    setenv("OPENSSL_armcap","0",1);
    tl_jni_set_oop_library_claim(NULL,NULL);
    G.prepared=true; ok=true;
    tl_log_line("oop: prepared V20 out of place: heap=%zu MiB xmem_used=%zu MiB data_imports_rebound=%u host_bound=%u",
                G.heap_bytes>>20,tl_xmem_used()>>20,1u,host_bound);
out:
    if (zip_open) tl_zip_close(&zip);
    if (gowned) free((void *)gbytes);
    if (cowned) free((void *)cbytes);
    pthread_mutex_unlock(&G.lock);
    if (ok) { int husk_oop_launch_claim(const char *, void *); tl_jni_set_oop_library_claim(husk_oop_launch_claim,NULL); }
    return ok;
}

static bool run_constructor(tl_lib *owner, uintptr_t entry, int argc, char **argv, char **envp, void *opaque) {
    (void)opaque; ++G.attempted;
    bool ok=oop_domain_init_gate(owner,entry,argc,argv,envp,&G.init);
    if (ok) { ++G.completed; return true; }
    uintptr_t base=(uintptr_t)tl_ld_lib_base(owner), pc=(uintptr_t)G.init.last_state.pc;
    tl_log_line("oop: constructor failed: %s entry+%#lx pc+%#lx gate=%d guest=%s",tl_ld_lib_name(owner),(unsigned long)(entry-base),
                (unsigned long)(pc>=base?pc-base:0),G.init.gate_result,bb_result_name(G.init.guest_result));
    return false;
}

/* System.loadLibrary: libgame.so (and its libc++_shared.so) are this image. */
int husk_oop_launch_claim(const char *leaf, void *opaque) {
    (void)opaque;
    bool game=!strcmp(leaf,"libgame.so"), cpp=!strcmp(leaf,"libc++_shared.so");
    if (!game && !cpp) return 0;
    pthread_mutex_lock(&G.lock);
    ++G.claims;
    int r=-1;
    if (!G.prepared || G.failed) goto out;
    if (cpp || G.loaded) { r=1; goto out; }   /* libc++ is initialized with libgame, once */
    /* This Java thread is the image's first guest thread (Android: the dlopen thread). */
    if (!oop_domain_thread_attach(G.domain,(uintptr_t)G.tcb) || !signal_mask_open(&G.mask,G.engine,(uintptr_t)G.tcb) ||
        !oop_domain_register_host(G.domain,(uintptr_t)tl_bionic_find("sigprocmask"),signal_mask_call,&G.mask)) {
        snprintf(G.failure,sizeof(G.failure),"guest_thread_setup"); goto failed; }
    G.mask_open=true;
    G.locale.gate.thread=pthread_self(); G.cxa.thread=pthread_self();
    G.init=(oop_init_context){.domain=G.domain,.stack=(uintptr_t)G.stack+GUEST_STACK_BYTES-16,.tls=(uintptr_t)G.tcb,
        .argv=(uintptr_t)G.stack+0x200,.envp=(uintptr_t)G.stack+0x220,.budget=50000000};
    if (!tl_ld_init_routed(G.game,run_constructor,NULL)) { snprintf(G.failure,sizeof(G.failure),"constructors %u/%u",G.completed,G.attempted); goto failed; }
    tl_log_line("oop: constructors %u/%u completed",G.completed,G.attempted);
    /* JNI_OnLoad through the per-thread bridge, on this thread, once. */
    void *onload=tl_ld_sym(G.game,"JNI_OnLoad");
    if (!onload || !jni_gate_open(&G.jni,G.engine,G.domain,(uintptr_t)G.tcb) || !oop_domain_register_entry(G.domain,(uintptr_t)onload)) {
        snprintf(G.failure,sizeof(G.failure),"jni_bridge"); goto failed; }
    G.jni.stack=G.init.stack; G.jni.lib=G.game; G.jni.budget=2000000000u;
    bb_state s={0}; bb_result gr; s.sp=G.init.stack; s.tpidr_el0=(uintptr_t)G.tcb; s.x[0]=G.jni.vm;
    oop_gate_result gate=oop_domain_call(G.domain,(uintptr_t)onload,OOP_ABI_INTEGER_0_TO_8,&s,50000000,&gr);
    if (gate!=OOP_GATE_OK || tl_jni_pending()) {
        char b[160]=""; if (tl_jni_pending() && tl_dvm_running()) tl_dvm_describe_pending(b,sizeof(b));
        snprintf(G.failure,sizeof(G.failure),"JNI_OnLoad gate=%d guest=%s %s",gate,bb_result_name(gr),b); goto failed; }
    G.onload_version=(int)s.x[0];
    if (!jni_gate_release_locals(&G.jni)) { snprintf(G.failure,sizeof(G.failure),"jni_locals"); goto failed; }
    /* Java natives the image defines dispatch into it; other threads enter as provisioned. */
    tl_dvm_set_foreign_natives(jni_foreign_resolve,jni_foreign_call,&G.jni);
    if (!oop_domain_enable_threads(G.domain) || !jni_gate_enable_threads(&G.jni)) { snprintf(G.failure,sizeof(G.failure),"threads"); goto failed; }
    G.loaded=true; r=1;
    tl_log_line("oop: libgame.so out of place: JNI_OnLoad returned %#x; natives dispatch to the guest; threads enabled",G.onload_version);
    goto out;
failed:
    G.failed=true;
    tl_log_line("oop: System.loadLibrary(\"game\") failed out of place: %s (not loaded in place)",G.failure);
out:
    pthread_mutex_unlock(&G.lock);
    return r;
}

void husk_oop_launch_get_status(husk_oop_launch_status *o) {
    if (!o) return;
    pthread_mutex_lock(&G.lock);
    *o=(husk_oop_launch_status){.prepared=G.prepared,.constructors_done=G.attempted && G.attempted==G.completed,
        .jni_onload_done=G.loaded,.threads_enabled=G.loaded,.constructors_attempted=G.attempted,.constructors_completed=G.completed,
        .loadlibrary_claims=G.claims,.jni_onload_version=G.onload_version,.heap_bytes=G.heap_bytes,.xmem_used=tl_xmem_used()};
    snprintf(o->failure,sizeof(o->failure),"%s",G.failure);
    pthread_mutex_unlock(&G.lock);
}
bool husk_oop_launch_views(const uint8_t **game, size_t *game_size, const uint8_t **cpp, size_t *cpp_size) {
    uint8_t *gw,*cw,*g,*c;
    if (!G.prepared || !tl_ld_oop_test_views(G.game,&g,&gw,game_size) || !tl_ld_oop_test_views(G.cpp,&c,&cw,cpp_size)) return false;
    *game=g; *cpp=c; return true;
}
struct jni_gate *husk_oop_launch_jni(void) { return G.loaded?&G.jni:NULL; }
struct oop_imports *husk_oop_launch_imports(void) { return G.imports; }
#endif
