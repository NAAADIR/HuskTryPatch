/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Only for the hash-verified V20 ELF in a separate macOS research process. */
#include "block_engine.h"
#include "husk-tl-ld.h"
#include "husk-tl-egl.h"
#include "husk-tl-xmem.h"
#include <assert.h>
#include <mach/mach.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

bool tl_ld_oop_test_views(tl_lib *, uint8_t **, uint8_t **, size_t *);
long tl_linux_syscall(long, long, long, long, long, long, long);
void tl_log_line(const char *fmt, ...) {
    va_list ap; va_start(ap,fmt); vfprintf(stderr,fmt,ap); fputc('\n',stderr); va_end(ap);
}
static long self_read(void *out, const void *from, size_t n) {
    struct iovec l={out,n}, r={(void *)from,n};
    return tl_linux_syscall(getpid(),(long)&l,1,(long)&r,1,0,270);
}
static void compare(bb_engine *e, uint64_t address, size_t n) {
    unsigned char a[32],b[32]; assert(n<=sizeof(a));
    assert(bb_read(e,address,a,n)); assert(self_read(b,(void *)(uintptr_t)address,n)==(long)n);
    assert(!memcmp(a,b,n));
}
static vm_prot_t protection(void *ptr) {
    vm_address_t address=(vm_address_t)ptr; vm_size_t n=0; natural_t depth=0;
    vm_region_submap_info_data_64_t info; mach_msg_type_number_t count=VM_REGION_SUBMAP_INFO_COUNT_64;
    assert(vm_region_recurse_64(mach_task_self(),&address,&n,&depth,(vm_region_recurse_info_t)&info,&count)==KERN_SUCCESS);
    assert(address<=(vm_address_t)ptr && (vm_address_t)ptr-address<n);
    return info.protection;
}
static bb_state state(uint64_t pc) { bb_state s={0}; s.pc=pc; s.x[30]=0xfeed0000; s.nzcv=0xa0000000; return s; }
static void run(bb_engine *e, bb_state *s) { assert(bb_run(e,s,0xfeed0000,100)==BB_STOP); assert(s->pc==0xfeed0000 && s->x[30]==0xfeed0000 && s->nzcv==0xa0000000); }
int main(int argc, char **argv) {
    assert(argc==5 && sysconf(_SC_PAGESIZE)==16384);
    assert(tl_egl_init(argv[3],argv[4],NULL,0)); assert(tl_ld_add_apk(argv[1]));
    tl_lib *lib=tl_ld_load("libgame.so"); assert(lib);
    assert(!tl_ld_init(lib)); /* No dependency or game constructors in this test. */
    tl_lib *cpp=tl_ld_find_lib("libc++_shared.so"); assert(cpp);
    uint8_t *guest,*write; size_t size;
    assert(tl_ld_oop_test_views(lib,&guest,&write,&size) && size>=0x29c1000);
    vm_prot_t gp=protection(guest), wp=protection(write);
    assert((gp&(VM_PROT_READ|VM_PROT_EXECUTE))==(VM_PROT_READ|VM_PROT_EXECUTE) && !(gp&VM_PROT_WRITE));
    assert((wp&(VM_PROT_READ|VM_PROT_WRITE))==(VM_PROT_READ|VM_PROT_WRITE) && !(wp&VM_PROT_EXECUTE));
    uint8_t *cache_rx,*cache_rw; assert(tl_xmem_alloc(16384,&cache_rx,&cache_rw));
    assert((protection(cache_rx)&(VM_PROT_WRITE|VM_PROT_EXECUTE))==VM_PROT_EXECUTE);
    assert((protection(cache_rw)&(VM_PROT_WRITE|VM_PROT_EXECUTE))==VM_PROT_WRITE);
    bb_engine *e=bb_attach(guest,write,size,8,cache_rw,cache_rx,16384); assert(e);
    /* Logical 4 KiB pages: executable LOAD and data LOAD; gap stays inaccessible. */
    assert(bb_protect(e,0,0x26cb000,BB_R|BB_X));
    assert(bb_protect(e,0x26cc000,0x29c1000-0x26cc000,BB_R));
    assert(bb_protect(e,0x29bf000,0x2000,BB_R|BB_W)); /* writable BSS */
    assert(!bb_read(e,(uintptr_t)guest+0x26cb000,&gp,1));
    FILE *f=fopen(argv[2],"rb"); assert(f); size_t textsz=0x26ca520;
    uint8_t *original=malloc(textsz); assert(original && fread(original,1,textsz,f)==textsz); fclose(f);
    assert(!memcmp(guest,original,textsz));
    void *entry=tl_ld_sym(lib,"_ZN17InitializeRequest12getRequestIDEv");
    assert(entry==guest+0x13a50b8);
    compare(e,(uintptr_t)entry,12);
    bb_state s=state((uintptr_t)entry); run(e,&s);
    assert(s.x[0]==(uintptr_t)guest+0x2337826); compare(e,s.x[0],16);
    bb_stats stats=bb_get_stats(e); assert(stats.native_blocks==1 && stats.interpreted_instructions==1);
    /* This real leaf loads a GLOB_DAT slot, relocated to a real game BSS symbol. */
    void *xml=tl_ld_sym(lib,"__xmlStructuredErrorContext");
    void *target=tl_ld_sym(lib,"xmlStructuredErrorContext");
    assert(xml==guest+0x20d5fc0 && target==guest+0x29bd458);
    uint64_t got=0; assert(bb_read(e,(uintptr_t)guest+0x287b5c8,&got,8));
    assert(got==(uintptr_t)target); compare(e,(uintptr_t)guest+0x287b5c8,8); compare(e,(uintptr_t)target,8);
    /* Cross-library R_AARCH64_ABS64, including the real addend of 16. */
    void *vtable=tl_ld_sym(cpp,"_ZTVN10__cxxabiv120__si_class_type_infoE"); assert(vtable);
    uint64_t external=0; assert(bb_read(e,(uintptr_t)guest+0x26ed848,&external,8));
    assert(external==(uintptr_t)vtable+16); compare(e,(uintptr_t)guest+0x26ed848,8);
    s=state((uintptr_t)xml); run(e,&s); assert(s.x[0]==got);
    stats=bb_get_stats(e); assert(stats.native_blocks==2 && stats.interpreted_instructions==3);
    printf("two real functions: %zu native blocks, %zu checked instructions\n",stats.native_blocks,stats.interpreted_instructions);
    /* A second real getter reads an unaligned 8-byte value across two 16 KiB host pages. */
    void *getter=tl_ld_sym(lib,"_ZN10BattleUnit17getBattleTreasureEv"); assert(getter==guest+0x1124fd0);
    uint32_t insn; memcpy(&insn,getter,4); assert(insn==0xf942cc00);
    uintptr_t boundary=(uintptr_t)guest+0x29c0000, addr=boundary-4;
    unsigned char saved[8]; assert(bb_read(e,addr,saved,8));
    uint64_t value=UINT64_C(0x9ac30d71e528b46f);
    stats=bb_get_stats(e); assert(bb_write(e,addr,&value,8)); assert(bb_get_stats(e).invalidations>stats.invalidations);
    compare(e,addr,8);
    s=state((uintptr_t)getter); s.x[0]=addr-(((insn>>10)&4095)*8); run(e,&s); assert(s.x[0]==value);
    assert(bb_write(e,addr,saved,8)); compare(e,addr,8);
    /* A real function's FMOV is outside this engine's implemented FP subset. */
    void *fp=tl_ld_sym(lib,"_ZN12SandbagScene20checkUnitStatusBonusEv"); assert(fp==guest+0x15c51f0);
    uint32_t fpinsn; memcpy(&fpinsn,fp,4); assert(fpinsn==0x1e2703e0);
    s=state((uintptr_t)fp); assert(bb_run(e,&s,0xfeed0000,100)==BB_UNSUPPORTED && s.pc==(uintptr_t)fp);
    assert(!memcmp(guest,original,textsz));
    puts("real relocated game: leaf, relocated GLOB_DAT load, 16 KiB crossing guest load and process_vm_readv: PASS");
    puts("original executable LOAD preserved; separate W^X cache; unsupported real FP instruction rejected: PASS");
    bb_destroy(e); free(original); return 0;
}
