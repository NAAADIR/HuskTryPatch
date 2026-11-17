/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "husk-tl-ld.h"
#include "husk-tl-internal.h"
#include "husk-tl-xmem.h"
#include "husk-jit-arena.h"
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int husk_oop_real_apk_matches(const char *);
int husk_oop_real_run(const char *,const char *,const char *);
int husk_oop_ios_run(const char *);
bool tl_ld_oop_real_open(const uint8_t *,size_t,const uint8_t *,size_t,tl_lib **,tl_lib **,unsigned *,unsigned *);
void tl_log_line(const char *fmt, ...) {
    va_list ap; va_start(ap,fmt); vfprintf(stderr,fmt,ap); fputc('\n',stderr); va_end(ap);
}
int main(int argc,char **argv)
{
    assert(argc==5);
    if (!strcmp(argv[1],"bad")) {
        assert(!husk_oop_real_apk_matches(argv[2]));
        assert(!husk_oop_real_run(argv[2],argv[3],argv[4]));
        puts("invalid APK safely rejected: PASS"); return 0;
    }
    if (!strcmp(argv[1],"synthetic-first")) {
        assert(husk_oop_ios_run("src/app/Husk/Resources/husk-oop-fixture.bin"));
        assert(!husk_oop_real_run(argv[2],argv[3],argv[4]));
        puts("synthetic diagnostic reserves allocator against real diagnostic: PASS"); return 0;
    }
    if (!strcmp(argv[1],"arena-first")) {
        char err[160]; assert(husk_jit_arena_open(1u<<20,0,err,sizeof(err)));
        assert(!husk_oop_real_run(argv[2],argv[3],argv[4]));
        puts("console arena reserves allocator against real diagnostic: PASS"); return 0;
    }
    if (!strcmp(argv[1],"missing-gl")) {
        assert(husk_oop_real_apk_matches(argv[2]));
        tl_zip z; char err[160]; assert(tl_zip_open(&z,argv[2],err,sizeof(err)));
        const uint8_t *g,*c; size_t gn,cn; bool go,co;
        assert(tl_zip_data(&z,tl_zip_find(&z,"lib/arm64-v8a/libgame.so"),50u<<20,&g,&gn,&go,err,sizeof(err)));
        assert(tl_zip_data(&z,tl_zip_find(&z,"lib/arm64-v8a/libc++_shared.so"),2u<<20,&c,&cn,&co,err,sizeof(err)));
        assert(husk_oop_claim_xmem() && tl_xmem_open(192u<<20,err,sizeof(err)));
        tl_lib *game=NULL,*cpp=NULL; unsigned stage=0,missing=0;
        assert(!tl_ld_oop_real_open(g,gn,c,cn,&game,&cpp,&stage,&missing) && stage==2 && missing==1 && !game && !cpp);
        assert(!tl_ld_find_lib("libgame.so") && !tl_ld_find_lib("libc++_shared.so"));
        if (go) free((void *)g); if (co) free((void *)c); tl_zip_close(&z);
        puts("private loader refuses unresolved GL import and publishes no library: PASS"); return 0;
    }
    assert(!strcmp(argv[1],"real"));
    assert(husk_oop_real_apk_matches(argv[2]));
    assert(husk_oop_real_run(argv[2],argv[3],argv[4]));
    printf("real diagnostic xmem allocated=%zu bytes; region=%zu bytes; cache=16384 bytes\n",tl_xmem_used(),tl_xmem_size());
    assert(!tl_ld_find_lib("libgame.so") && !tl_ld_find_lib("libc++_shared.so"));
    assert(husk_oop_xmem_claimed() && !husk_oop_real_run(argv[2],argv[3],argv[4]));
    puts("private real APK loader and one-use allocator: PASS");
}
