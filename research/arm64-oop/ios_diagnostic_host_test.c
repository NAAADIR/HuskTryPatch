/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "husk-jit-arena.h"
#include "husk-tl-ld.h"
#include "husk-tl-xmem.h"
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
int husk_oop_ios_run(const char *);
void tl_log_line(const char *fmt, ...) {
    va_list ap; va_start(ap,fmt); vfprintf(stderr,fmt,ap); fputc('\n',stderr); va_end(ap);
}
int main(int argc, char **argv)
{
    assert(argc==4); char err[160];
    if (!strcmp(argv[1],"arena-first")) {
        assert(husk_jit_arena_open(1u<<20,0,err,sizeof(err)));
        assert(!husk_oop_ios_run(argv[2]));
        assert(husk_jit_arena_is_open());
        puts("existing console arena correctly refused diagnostic: PASS"); return 0;
    }
    if (!strcmp(argv[1],"bad-fixture")) {
        assert(!husk_oop_ios_run(argv[2]));
        assert(!tl_ld_find_lib("husk-oop-fixture"));
        puts("untrusted fixture rejected before loading: PASS"); return 0;
    }
    assert(!strcmp(argv[1],"smoke"));
    assert(husk_oop_ios_run(argv[2]));
    assert(!tl_ld_find_lib("husk-oop-fixture"));
    assert(!husk_jit_arena_open(1u<<20,0,err,sizeof(err)));
    /* A later normal guest load still uses the production patcher. */
    tl_lib *lib=tl_ld_load(argv[3]); assert(lib && tl_ld_init(lib));
    uint8_t *base=tl_ld_lib_base(lib); assert(base && tl_ld_sym(lib,"gcore_tick")==base+0x2664);
    uint32_t svc; memcpy(&svc,base+0x4564,4);
    assert(svc!=0xd4000001u && (svc&0xfc000000u)==0x14000000u);
    puts("diagnostic isolation and later production loader: PASS");
}
