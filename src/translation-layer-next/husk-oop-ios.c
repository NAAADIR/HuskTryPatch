/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Opt-in diagnostic only: the fixture is never executed at its guest address. */
#ifdef HUSK_OOP_IOS_DIAG
#include "../../research/arm64-oop/block_engine.h"
#include "husk-tl-ld.h"
#include "husk-tl-xmem.h"
#include "husk-jit-arena.h"
#include "husk-tl-internal.h"
#include <CommonCrypto/CommonDigest.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

tl_lib *tl_ld_oop_fixture_open(const uint8_t *, size_t, void *);
void tl_ld_oop_fixture_close(tl_lib *);
bool tl_ld_oop_test_views(tl_lib *, uint8_t **, uint8_t **, size_t *);
long tl_linux_syscall(long, long, long, long, long, long, long);
extern const char *husk_native_loaded_apk(void) __attribute__((weak_import));

static uint64_t fixture_host(uint64_t value) { return value + 7; }
struct check_gate { uintptr_t ret, marker, data; uint64_t expected; unsigned calls; };
static bool gate(bb_state *s, void *opaque)
{
    struct check_gate *c=opaque;
    if (s->pc!=(uintptr_t)fixture_host || s->x[30]!=c->ret || s->x[12]!=c->marker ||
        s->x[9]!=c->data || s->x[0]!=c->expected || s->nzcv!=0xa0000000) return false;
    ++c->calls; s->x[0]=fixture_host(s->x[0]); return true;
}
static bb_state initial(uint8_t *base, void *entry)
{
    bb_state s={0}; for (unsigned i=0;i<31;++i) s.x[i]=0xabc000+i;
    s.pc=(uintptr_t)entry; s.sp=(uintptr_t)base+0x8000; s.x[30]=0xfeed0000; s.nzcv=0xa0000000; return s;
}
static long self_read(void *out, const void *from, size_t n)
{
    struct iovec local={out,n}, remote={(void *)from,n};
    return tl_linux_syscall(getpid(),(long)&local,1,(long)&remote,1,0,270);
}
enum { JIT, ALLOC, ELF, RELOC, NATIVE, CALLS, HOST, MEMORY, READV, INVALIDATE, NSTAGES };
static const char *const stage_names[NSTAGES]={"jit_ready","allocator","elf_load","relocations",
    "native_execution","guest_calls","host_gate","memory_coherence","process_vm_readv","cache_invalidation"};
#define REQUIRE(stage, condition, category) do { if (!(condition)) { failed=(category); goto done; } passed[stage]=true; } while (0)

void husk_oop_ios_preflight_fail(int jit_ready)
{
    for (unsigned i=0;i<NSTAGES;++i)
        fprintf(stderr,"HUSK-OOP-IOS %s=%s\n",stage_names[i],i==JIT && jit_ready ? "pass" : "fail");
    fprintf(stderr,"HUSK-OOP-IOS error_category=%s\n",jit_ready ? "fixture_missing" : "jit_unavailable");
    fprintf(stderr,"HUSK-OOP-IOS overall=fail\n");
}

/* path must be the app's own bundled fixture. Returns 1 on pass, 0 on failure. */
int husk_oop_ios_run(const char *path)
{
    bool passed[NSTAGES]={0}; const char *failed="unknown";
    uint8_t *file=NULL, *guest=NULL, *write=NULL, *cache_rx=NULL, *cache_rw=NULL;
    tl_lib *lib=NULL; bb_engine *engine=NULL; size_t size=0; FILE *f=NULL;
    static const unsigned char expected[CC_SHA256_DIGEST_LENGTH]={
        0xe5,0x09,0xaf,0x4b,0xd7,0x5f,0x52,0x2c,0x9b,0x2e,0xf6,0x79,0xd7,0x35,0x3e,0x82,
        0x81,0x53,0x8b,0xf4,0xda,0xfe,0x13,0x8c,0x12,0x69,0x5e,0xca,0x10,0x3f,0x26,0x30};
    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    fprintf(stderr,"HUSK-OOP-IOS start=1\n");
#ifndef HUSK_OOP_HOST_TEST
    tl_dual_mapping *(*get_mapping)(void)=(tl_dual_mapping *(*)(void))dlsym(RTLD_DEFAULT,"husk_ios_jit_get_mapping");
    tl_dual_mapping *mapping=get_mapping ? get_mapping() : NULL;
    REQUIRE(JIT,mapping && mapping->rw_addr && mapping->rx_addr && mapping->size,"jit_unavailable");
#else
    passed[JIT]=true;
#endif
    fprintf(stderr,"HUSK-OOP-IOS jit_ready=pass\n");
    REQUIRE(ALLOC,(!husk_native_loaded_apk || !husk_native_loaded_apk()) &&
            tl_xmem_is_unused() && husk_oop_claim_xmem(),"allocator_busy");
    char err[160];
    if (!tl_xmem_open(32u<<20,err,sizeof(err)) || !tl_xmem_alloc(16384,&cache_rx,&cache_rw)) {
        passed[ALLOC]=false; failed="allocator_unavailable"; goto done;
    }
    fprintf(stderr,"HUSK-OOP-IOS allocator=pass\n");
    /* A signed bundle's fixture must match the one audited by the harness. */
    REQUIRE(ELF,path && (f=fopen(path,"rb")),"fixture_missing");
    passed[ELF]=false;
    REQUIRE(ELF,(file=malloc(0x6000)) && fread(file,1,0x6000,f)==0x6000 && fgetc(f)==EOF,"fixture_size");
    fclose(f); f=NULL; passed[ELF]=false;
    CC_SHA256(file,0x6000,hash);
    REQUIRE(ELF,!memcmp(hash,expected,sizeof(hash)),"fixture_checksum");
    passed[ELF]=false;
    lib=tl_ld_oop_fixture_open(file,0x6000,(void *)fixture_host);
    REQUIRE(ELF,lib && tl_ld_oop_test_views(lib,&guest,&write,&size) && size>=0xc000,"elf_load");
    fprintf(stderr,"HUSK-OOP-IOS elf_load=pass\n");
    void *entry=tl_ld_sym(lib,"fixture_entry"), *nested=tl_ld_sym(lib,"fixture_nested");
    void *marker=tl_ld_sym(lib,"fixture_marker"), *ret=tl_ld_sym(lib,"fixture_host_return");
    void *middle=tl_ld_sym(lib,"fixture_middle"), *nested_ret=tl_ld_sym(lib,"fixture_nested_return");
    REQUIRE(RELOC,entry==guest+0x1000 && nested && marker && ret && middle && nested_ret,"symbol_lookup");
    passed[RELOC]=false;
    uint64_t *data=(uint64_t *)(guest+0x4000);
    REQUIRE(RELOC,data[0]==(uintptr_t)(guest+0x4020) && data[1]==(uintptr_t)fixture_host &&
            data[2]==(uintptr_t)nested && data[4]==37,"relocation_values");
    fprintf(stderr,"HUSK-OOP-IOS relocations=pass\n");
    engine=bb_attach(guest,write,size,8,cache_rw,cache_rx,16384);
    if (!engine || !bb_protect(engine,0,0x4000,BB_R|BB_X) ||
        !bb_protect(engine,0x1000,4096,BB_R|BB_W|BB_X) ||
        !bb_protect(engine,0x4000,size-0x4000,BB_R|BB_W)) { failed="guest_permissions"; goto done; }
    struct check_gate check={(uintptr_t)ret,(uintptr_t)marker,(uintptr_t)(guest+0x4000),42,0};
    if (!bb_set_host_gate(engine,(uintptr_t)fixture_host,gate,&check)) { failed="gate_setup"; goto done; }
    uint8_t original[0x4c], guest_code[0x4c], remote_code[0x4c];
    memcpy(original,file+0x1000,sizeof(original));
    if (!bb_read(engine,(uintptr_t)entry,guest_code,sizeof(guest_code)) || memcmp(original,guest_code,sizeof(original))) {
        failed="initial_code"; goto done;
    }
    fprintf(stderr,"HUSK-OOP-IOS native_entry=begin\n");
    bb_state s=initial(guest,entry);
    REQUIRE(CALLS,bb_run(engine,&s,(uintptr_t)middle,100)==BB_STOP && s.x[30]==(uintptr_t)entry+0x18 &&
            bb_run(engine,&s,(uintptr_t)nested,100)==BB_STOP && s.x[30]==(uintptr_t)nested_ret &&
            bb_run(engine,&s,0xfeed0000,100)==BB_STOP,"guest_control_flow");
    REQUIRE(HOST,check.calls==1 && s.x[0]==49,"host_gate");
    bool preserved=s.sp==(uintptr_t)guest+0x8000 && s.x[29]==0xabc01d && s.x[30]==0xfeed0000 && s.nzcv==0xa0000000;
    for (unsigned i=19;i<29;++i) preserved=preserved && s.x[i]==0xabc000+i;
    REQUIRE(NATIVE,preserved && bb_get_stats(engine).native_blocks>=2,"registers_or_native_code");
    REQUIRE(MEMORY,data[4]==49 && bb_read(engine,(uintptr_t)entry,guest_code,sizeof(guest_code)) &&
            !memcmp(original,guest_code,sizeof(original)),"guest_memory");
    uint64_t guest_data[5], remote_data[5];
    REQUIRE(READV,bb_read(engine,(uintptr_t)data,guest_data,sizeof(guest_data)) &&
            self_read(remote_data,data,sizeof(remote_data))==sizeof(remote_data) && !memcmp(guest_data,remote_data,sizeof(guest_data)) &&
            self_read(remote_code,entry,sizeof(remote_code))==sizeof(remote_code) && !memcmp(original,remote_code,sizeof(original)),"syscall_read");
    s=initial(guest,nested); s.x[0]=37;
    if (bb_run(engine,&s,0xfeed0000,100)!=BB_STOP || s.x[0]!=42) { failed="cache_prime"; goto done; }
    bb_stats before=bb_get_stats(engine); uint32_t changed=0x91001800; uint64_t value=37;
    if (!bb_write(engine,(uintptr_t)nested,&changed,4) || bb_get_stats(engine).invalidations<=before.invalidations ||
        !bb_write(engine,(uintptr_t)(guest+0x4020),&value,8)) { failed="cache_write"; goto done; }
    check.expected=43; s=initial(guest,entry);
    REQUIRE(INVALIDATE,bb_run(engine,&s,0xfeed0000,100)==BB_STOP && s.x[0]==50 && check.calls==2 && data[4]==50,"cache_retranslation");
    failed=NULL;
done:
    if (f) fclose(f);
    if (engine) bb_destroy(engine);
    if (lib) tl_ld_oop_fixture_close(lib);
    free(file);
    for (unsigned i=0;i<NSTAGES;++i) fprintf(stderr,"HUSK-OOP-IOS %s=%s\n",stage_names[i],passed[i]?"pass":"fail");
    if (failed) fprintf(stderr,"HUSK-OOP-IOS error_category=%s\n",failed);
    fprintf(stderr,"HUSK-OOP-IOS overall=%s\n",failed?"fail":"pass");
    return failed ? 0 : 1;
}
#undef REQUIRE
#endif
