/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Research-only integration: never call the unrewritten fixture directly. */
#include "block_engine.h"
#include "husk-tl-ld.h"
#include "husk-tl-xmem.h"
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <unistd.h>

bool tl_ld_oop_test_views(tl_lib *, uint8_t **, uint8_t **, size_t *);
long tl_linux_syscall(long, long, long, long, long, long, long);
void tl_log_line(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt); vfprintf(stderr,fmt,ap); fputc('\n',stderr); va_end(ap);
}
static long self_read(void *out, const void *from, size_t n) {
    struct iovec local={out,n}, remote={(void *)from,n};
    return tl_linux_syscall(getpid(),(long)&local,1,(long)&remote,1,0,270);
}
static uint64_t fixture_host(uint64_t value) { return value + 7; }
struct gate_check { uintptr_t ret, marker, data; unsigned calls; uint64_t expected; };
static bool gate(bb_state *s, void *opaque) {
    struct gate_check *c=opaque;
    if (s->pc!=(uintptr_t)fixture_host || s->x[30]!=c->ret || s->x[12]!=c->marker ||
        s->x[9]!=c->data || s->x[0]!=c->expected || s->nzcv!=0xa0000000) return false;
    ++c->calls; s->x[0]=fixture_host(s->x[0]); return true;
}
static bb_state initial(uint8_t *base, void *entry) {
    bb_state s={0}; for (unsigned i=0;i<31;++i) s.x[i]=0xabc000+i;
    s.pc=(uintptr_t)entry; s.sp=(uintptr_t)base+0x8000; s.x[30]=0xfeed0000; s.nzcv=0xa0000000; return s;
}
int main(int argc, char **argv) {
    assert(argc==2 && sysconf(_SC_PAGESIZE)==16384);
    tl_ld_interpose("fixture_host",(void *)fixture_host);
    tl_lib *lib=tl_ld_load(argv[1]); assert(lib);
    uint8_t *guest,*write; size_t size;
    assert(tl_ld_oop_test_views(lib,&guest,&write,&size) && size>=0xc000);
    void *entry=tl_ld_sym(lib,"fixture_entry"), *nested=tl_ld_sym(lib,"fixture_nested");
    void *marker=tl_ld_sym(lib,"fixture_marker"), *ret=tl_ld_sym(lib,"fixture_host_return");
    void *middle=tl_ld_sym(lib,"fixture_middle"), *nested_ret=tl_ld_sym(lib,"fixture_nested_return");
    assert(entry==guest+0x1000 && nested && marker && ret && middle && nested_ret);
    uint64_t *data=(uint64_t *)(guest+0x4000);
    assert(data[0]==(uintptr_t)(guest+0x4020) && data[1]==(uintptr_t)fixture_host && data[2]==(uintptr_t)nested && data[4]==37);
    uint8_t *cache_rx,*cache_rw;
    assert(tl_xmem_alloc(16384,&cache_rx,&cache_rw));
    assert(cache_rx>=guest+size || cache_rx+16384<=guest);
    assert(!bb_attach(guest,write,size,8,write,cache_rx,16384));
    bb_engine *e=bb_attach(guest,write,size,8,cache_rw,cache_rx,16384); assert(e);
    assert(bb_protect(e,0,0x4000,BB_R|BB_X));
    assert(bb_protect(e,0x1000,4096,BB_R|BB_W|BB_X));
    assert(bb_protect(e,0x4000,size-0x4000,BB_R|BB_W));
    struct gate_check check={(uintptr_t)ret,(uintptr_t)marker,(uintptr_t)(guest+0x4000),0,42};
    assert(bb_set_host_gate(e,(uintptr_t)fixture_host,gate,&check));
    uint8_t before[0x4c], original[0x4c], ordinary[0x4c], syscall_bytes[0x4c];
    FILE *fixture=fopen(argv[1],"rb"); assert(fixture && !fseek(fixture,0x1000,SEEK_SET));
    assert(fread(original,1,sizeof(original),fixture)==sizeof(original)); fclose(fixture);
    memcpy(before,entry,sizeof(before));
    assert(!memcmp(before,original,sizeof(before)));
    uint64_t guest_data[5], syscall_data[5];
    assert(bb_read(e,(uintptr_t)data,guest_data,sizeof(guest_data)));
    assert(self_read(syscall_data,data,sizeof(syscall_data))==sizeof(syscall_data));
    assert(!memcmp(guest_data,syscall_data,sizeof(guest_data)));
    bb_state s=initial(guest,entry);
    assert(bb_run(e,&s,(uintptr_t)middle,100)==BB_STOP && s.x[30]==(uintptr_t)entry+0x18);
    assert(bb_run(e,&s,(uintptr_t)nested,100)==BB_STOP && s.x[30]==(uintptr_t)nested_ret);
    assert(bb_run(e,&s,0xfeed0000,100)==BB_STOP);
    assert(s.x[0]==49 && check.calls==1 && s.sp==(uintptr_t)guest+0x8000 && s.x[29]==0xabc01d && s.x[30]==0xfeed0000 && s.nzcv==0xa0000000);
    assert(data[4]==49); /* guest STR through the relocated data pointer's page */
    for (unsigned i=19;i<29;++i) assert(s.x[i]==0xabc000+i);
    assert(bb_read(e,(uintptr_t)entry,ordinary,sizeof(ordinary)) && !memcmp(before,ordinary,sizeof(before)));
    assert(self_read(syscall_bytes,entry,sizeof(syscall_bytes))==sizeof(syscall_bytes) && !memcmp(before,syscall_bytes,sizeof(before)));
    bb_stats st=bb_get_stats(e); assert(st.native_blocks>=2 && st.interpreted_instructions>0);
    /* Prime the exact block that the following write must invalidate. */
    s=initial(guest,nested); s.x[0]=37;
    assert(bb_run(e,&s,0xfeed0000,100)==BB_STOP && s.x[0]==42);
    st=bb_get_stats(e);
    /* Serialize a code write through the loader's alias and require a new translation. */
    uint32_t changed=0x91001800; /* add x0, x0, #6 */
    assert(bb_write(e,(uintptr_t)nested,&changed,4));
    uint32_t readback=0; assert(bb_read(e,(uintptr_t)nested,&readback,4) && readback==changed);
    assert(self_read(&readback,nested,4)==4 && readback==changed);
    assert(bb_get_stats(e).invalidations>st.invalidations);
    uint64_t value=37; assert(bb_write(e,(uintptr_t)(guest+0x4020),&value,8));
    check.expected=43;
    s=initial(guest,entry); assert(bb_run(e,&s,0xfeed0000,100)==BB_STOP && s.x[0]==50 && check.calls==2);
    assert(data[4]==50);
    uint32_t unsupported=0xd4000001; /* svc #0: deliberately no unrewritten fallback */
    assert(bb_write(e,(uintptr_t)nested,&unsupported,4));
    s=initial(guest,nested); assert(bb_run(e,&s,0xfeed0000,100)==BB_UNSUPPORTED && s.pc==(uintptr_t)nested);
    s=initial(guest,entry); s.pc=(uintptr_t)fixture_host+4;
    assert(bb_run(e,&s,0xfeed0000,100)==BB_MEMORY && s.pc==(uintptr_t)fixture_host+4);
    assert(bb_protect(e,0x1000,4096,BB_R|BB_X));
    assert(!bb_write(e,(uintptr_t)nested,&changed,4));
    /* A real 16 KiB host permission boundary as well as the engine's logical check. */
    assert(bb_protect(e,0x8000,0x4000,0));
    assert(mprotect(guest+0x8000,0x4000,PROT_NONE)==0);
    uint64_t cross=0; assert(!bb_read(e,(uintptr_t)(guest+0x7ffc),&cross,8));
    assert(self_read(&cross,guest+0x8000,4)<0);
    assert(mprotect(guest+0x8000,0x4000,PROT_READ|PROT_EXEC)==0);
    assert(bb_protect(e,0x8000,0x4000,BB_R|BB_W));
    assert(bb_read(e,(uintptr_t)(guest+0x7ffc),&cross,8));
    assert(self_read(&cross,guest+0x7ffc,8)==8);
    st=bb_get_stats(e);
    printf("native blocks: %zu; checked instructions: %zu; host calls: %u; invalidations: %zu\n",
           st.native_blocks,st.interpreted_instructions,check.calls,st.invalidations);
    bb_destroy(e);
    puts("real loader, ELF relocations, separate native cache, nested calls, host gate, guest reads and invalidation: PASS");
}
