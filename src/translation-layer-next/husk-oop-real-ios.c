/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Development diagnostic: hash-verified V20 only, no game initialization. */
#ifdef HUSK_OOP_IOS_DIAG
#include "../../research/arm64-oop/block_engine.h"
#include "husk-tl-internal.h"
#include "husk-tl-ld.h"
#include "husk-tl-egl.h"
#include "husk-tl-xmem.h"
#include "husk-jit-arena.h"
#include <CommonCrypto/CommonDigest.h>
#include <dlfcn.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

bool tl_ld_oop_real_open(const uint8_t *,size_t,const uint8_t *,size_t,tl_lib **,tl_lib **,unsigned *,unsigned *);
void tl_ld_oop_fixture_close(tl_lib *);
bool tl_ld_oop_test_views(tl_lib *,uint8_t **,uint8_t **,size_t *);
long tl_linux_syscall(long,long,long,long,long,long,long);
extern const char *husk_native_loaded_apk(void) __attribute__((weak_import));

enum { APK,JIT,ALLOC,DEPS,ELF,RELOCS,NATIVE,MEMORY,READV,PAGE,CODE,NSTAGES };
static const char *const names[NSTAGES]={"apk_verified","jit_ready","allocator","dependencies","real_elf_load",
    "relocations","real_native_execution","guest_memory_coherence","process_vm_readv","page_boundary","original_code_preserved"};
static const char apk_hash[]="e571122a8706b2f815bf96e9b4b6549f6fc05c20bfe7d5890775ed7a2dfa3cd5";
static const char game_hash[]="b7e856193c378edd17ac12b0551e001535454d112c9e4e346e83d3bd934e0281";
static const char cpp_hash[]="ca8a1118abdd5316828fe895543062494b9c0225b8b861534447e708e16bbdde";
static bool hash_matches(const uint8_t *data, size_t len, const char *expected)
{
    if (!data || len>UINT_MAX) return false;
    unsigned char hash[CC_SHA256_DIGEST_LENGTH]; static const char hex[]="0123456789abcdef";
    CC_SHA256(data,(CC_LONG)len,hash);
    for (unsigned i=0;i<sizeof(hash);i++) if (expected[2*i]!=hex[hash[i]>>4] || expected[2*i+1]!=hex[hash[i]&15]) return false;
    return true;
}
int husk_oop_real_apk_matches(const char *path)
{
    tl_zip zip={0}; char err[160];
    if (!path || !tl_zip_open(&zip,path,err,sizeof(err))) return 0;
    bool ok=hash_matches(zip.map,zip.size,apk_hash); tl_zip_close(&zip); return ok;
}
static bool entry(const tl_zip *z,const char *name,size_t size,const char *hash,uint8_t **out)
{
    const tl_zip_entry *e=tl_zip_find(z,name); const uint8_t *data=NULL; size_t n=0; bool owned=false; char err[160];
    if (!e || e->usize!=size || !tl_zip_data(z,e,size,&data,&n,&owned,err,sizeof(err)) || n!=size) return false;
    uint8_t *copy;
    if (owned) copy=(uint8_t *)data;
    else { copy=malloc(n); if (copy) memcpy(copy,data,n); }
    if (!copy || !hash_matches(copy,n,hash)) { free(copy); return false; }
    *out=copy; return true;
}
static long self_read(void *out,const void *from,size_t n)
{
    struct iovec l={out,n},r={(void *)from,n};
    return tl_linux_syscall(getpid(),(long)&l,1,(long)&r,1,0,270);
}
static bool compare(bb_engine *e,uint64_t addr,size_t n)
{
    unsigned char a[32],b[32];
    return n<=sizeof(a) && bb_read(e,addr,a,n) && self_read(b,(void *)(uintptr_t)addr,n)==(long)n && !memcmp(a,b,n);
}
static bb_state initial(uint64_t pc) { bb_state s={0}; s.pc=pc; s.x[30]=0xfeed0000; s.nzcv=0xa0000000; return s; }
static bool run(bb_engine *e,bb_state *s)
{
    return bb_run(e,s,0xfeed0000,100)==BB_STOP && s->pc==0xfeed0000 && s->x[30]==0xfeed0000 && s->nzcv==0xa0000000;
}
static void report(const bool *passed,const char *error,int unresolved,bb_stats stats)
{
    for (unsigned i=0;i<NSTAGES;i++) fprintf(stderr,"HUSK-OOP-REAL %s=%s\n",names[i],passed[i]?"pass":"fail");
    fprintf(stderr,"HUSK-OOP-REAL unresolved_imports=%d\n",unresolved);
    fprintf(stderr,"HUSK-OOP-REAL native_blocks=%zu native_instructions=%zu fallback_instructions=%zu\n",
            stats.native_blocks,stats.native_instructions,stats.interpreted_instructions);
    fprintf(stderr,"HUSK-OOP-REAL error_category=%s\n",error?error:"none");
    fprintf(stderr,"HUSK-OOP-REAL overall=%s\n",error?"fail":"pass");
}
void husk_oop_real_preflight_fail(int jit_ready)
{
    bool passed[NSTAGES]={0}; passed[JIT]=jit_ready!=0;
    bb_stats stats={0}; report(passed,jit_ready?"apk_missing":"jit_unavailable",-1,stats);
}
#define CHECK(c,why) do { if (!(c)) { error=(why); goto done; } } while (0)
int husk_oop_real_run(const char *apk,const char *egl,const char *gles)
{
    bool passed[NSTAGES]={0}; const char *error="unknown"; int unresolved=-1; unsigned phase=0,missing=0;
    tl_zip zip={0}; bool zip_open=false; uint8_t *game=NULL,*cpp=NULL,*guest=NULL,*write=NULL,*cache_rx=NULL,*cache_rw=NULL;
    tl_lib *lib=NULL,*dep=NULL; bb_engine *engine=NULL; size_t size=0; bb_stats stats={0}; char err[160];
    fprintf(stderr,"HUSK-OOP-REAL start=1\n");
    CHECK(apk && tl_zip_open(&zip,apk,err,sizeof(err)),"apk_missing"); zip_open=true;
    CHECK(hash_matches(zip.map,zip.size,apk_hash),"apk_mismatch");
    CHECK(entry(&zip,"lib/arm64-v8a/libgame.so",42564848,game_hash,&game) &&
          entry(&zip,"lib/arm64-v8a/libc++_shared.so",919888,cpp_hash,&cpp),"apk_entry_mismatch");
    passed[APK]=true;
#ifndef HUSK_OOP_HOST_TEST
    tl_dual_mapping *(*get_mapping)(void)=(tl_dual_mapping *(*)(void))dlsym(RTLD_DEFAULT,"husk_ios_jit_get_mapping");
    tl_dual_mapping *mapping=get_mapping?get_mapping():NULL;
    CHECK(mapping && mapping->rw_addr && mapping->rx_addr && mapping->size,"jit_unavailable");
#endif
    passed[JIT]=true;
    CHECK((!husk_native_loaded_apk || !husk_native_loaded_apk()) && tl_xmem_is_unused() && husk_oop_claim_xmem(),"allocator_busy");
    CHECK((!husk_native_loaded_apk || !husk_native_loaded_apk()) && tl_xmem_is_unused(),"allocator_busy");
    CHECK(tl_xmem_open(192u<<20,err,sizeof(err)) && tl_xmem_size()-tl_xmem_used()>=(64u<<20) &&
          tl_xmem_alloc(16384,&cache_rx,&cache_rw),"allocator_unavailable");
    passed[ALLOC]=true;
    CHECK(egl && tl_egl_init(egl,gles,NULL,0),"angle_unavailable");
    bool loaded=tl_ld_oop_real_open(game,42564848,cpp,919888,&lib,&dep,&phase,&missing);
    passed[ELF]=phase>=1; passed[DEPS]=phase>=2; unresolved=phase>=2?(int)missing:-1;
    CHECK(loaded,phase==0?"elf_load":phase==1?"dependency_unsupported":missing?"unresolved_imports":"relocation_failed"); passed[RELOCS]=true;
    CHECK(tl_ld_oop_test_views(lib,&guest,&write,&size) && size>=0x29c1000 && !tl_ld_init(lib) &&
          !tl_ld_find_lib("libgame.so") && !tl_ld_find_lib("libc++_shared.so"),"loader_isolation");
    engine=bb_attach(guest,write,size,8,cache_rw,cache_rx,16384);
    CHECK(engine && bb_protect(engine,0,0x26cb000,BB_R|BB_X) &&
          bb_protect(engine,0x26cc000,0x29c1000-0x26cc000,BB_R) &&
          bb_protect(engine,0x29bf000,0x2000,BB_R|BB_W),"guest_permissions");
    CHECK(!memcmp(guest,game,0x26ca520),"initial_code");
    void *id=tl_ld_sym(lib,"_ZN17InitializeRequest12getRequestIDEv");
    void *xml=tl_ld_sym(lib,"__xmlStructuredErrorContext"), *target=tl_ld_sym(lib,"xmlStructuredErrorContext");
    void *vt=tl_ld_sym(dep,"_ZTVN10__cxxabiv120__si_class_type_infoE");
    CHECK(id==guest+0x13a50b8 && xml==guest+0x20d5fc0 && target==guest+0x29bd458 && vt,"symbol_lookup");
    uint64_t slot=0,external=0; uint8_t code[12];
    CHECK(bb_read(engine,(uintptr_t)id,code,sizeof(code)) && !memcmp(code,game+0x13a50b8,sizeof(code)) &&
          bb_read(engine,(uintptr_t)guest+0x287b5c8,&slot,8) && slot==(uintptr_t)target &&
          bb_read(engine,(uintptr_t)guest+0x26ed848,&external,8) && external==(uintptr_t)vt+16,"guest_data");
    passed[MEMORY]=true;
    CHECK(compare(engine,(uintptr_t)id,12) && compare(engine,(uintptr_t)guest+0x287b5c8,8) &&
          compare(engine,(uintptr_t)guest+0x26ed848,8) && compare(engine,(uintptr_t)target,8),"syscall_read"); passed[READV]=true;
    fprintf(stderr,"HUSK-OOP-REAL native_entry=begin\n");
    bb_state s=initial((uintptr_t)id);
    CHECK(run(engine,&s) && s.x[0]==(uintptr_t)guest+0x2337826 && compare(engine,s.x[0],16),"request_id");
    s=initial((uintptr_t)xml); CHECK(run(engine,&s) && s.x[0]==slot,"relocated_load");
    stats=bb_get_stats(engine); CHECK(stats.native_blocks==2 && stats.native_instructions==3 && stats.interpreted_instructions==3,"execution_coverage");
    void *getter=tl_ld_sym(lib,"_ZN10BattleUnit17getBattleTreasureEv");
    CHECK(getter==guest+0x1124fd0,"getter_symbol"); uint32_t insn; memcpy(&insn,getter,4); CHECK(insn==0xf942cc00,"getter_opcode");
    uintptr_t addr=(uintptr_t)guest+0x29c0000-4; uint8_t saved[8]; uint64_t value=UINT64_C(0x9ac30d71e528b46f);
    CHECK(bb_read(engine,addr,saved,8),"boundary_read"); stats=bb_get_stats(engine);
    CHECK(bb_write(engine,addr,&value,8) && bb_get_stats(engine).invalidations>stats.invalidations && compare(engine,addr,8),"boundary_write");
    s=initial((uintptr_t)getter); s.x[0]=addr-(((insn>>10)&4095)*8);
    CHECK(run(engine,&s) && s.x[0]==value && bb_write(engine,addr,saved,8) && compare(engine,addr,8),"boundary_load"); passed[PAGE]=true;
    void *fp=tl_ld_sym(lib,"_ZN12SandbagScene20checkUnitStatusBonusEv");
    CHECK(fp==guest+0x15c51f0,"unsupported_symbol"); memcpy(&insn,fp,4); CHECK(insn==0x1e2703e0,"unsupported_opcode");
    s=initial((uintptr_t)fp); CHECK(bb_run(engine,&s,0xfeed0000,100)==BB_UNSUPPORTED && s.pc==(uintptr_t)fp,"unsupported_instruction");
    passed[NATIVE]=true;
    CHECK(!memcmp(guest,game,0x26ca520),"code_modified"); passed[CODE]=true;
    error=NULL;
done:
    if (engine) { stats=bb_get_stats(engine); bb_destroy(engine); }
    if (lib) tl_ld_oop_fixture_close(lib); if (dep) tl_ld_oop_fixture_close(dep);
    free(game); free(cpp); if (zip_open) tl_zip_close(&zip);
    report(passed,error,unresolved,stats); return error?0:1;
}
#undef CHECK
#endif
