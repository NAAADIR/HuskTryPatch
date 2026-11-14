/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "block_engine.h"
#include "arm64_oop.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
long prototype_read(void *, const void *, size_t);
#define PAGE 4096
#define END UINT64_C(0xfeed0000)
static uint32_t adr(unsigned rd, int d) { unsigned i=(unsigned)d&0x1fffff; return 0x10000000 | ((i&3)<<29) | ((i>>2)<<5) | rd; }
static uint32_t adrp(unsigned rd, int pages) { return adr(rd,pages) | 0x80000000u; }
static uint32_t movz(unsigned r, unsigned v) { return 0x52800000 | ((v&0xffff)<<5) | r; }
static bb_engine *make(const uint32_t *p, size_t n, size_t slots) {
    unsigned char *image=calloc(1,PAGE*4); assert(image && n*4<PAGE*4); memcpy(image,p,n*4);
    bb_engine *e=bb_create(image,PAGE*4,slots); free(image); assert(e);
    assert(bb_protect(e,0,PAGE,BB_R|BB_W|BB_X)); assert(bb_protect(e,PAGE,PAGE*3,BB_R|BB_W)); return e;
}
static bb_state start(bb_engine *e, size_t off) {
    bb_state s={0}; s.pc=bb_base(e)+off; s.sp=bb_base(e)+PAGE*4; s.x[30]=END; return s;
}
static void run(bb_engine *e, bb_state *s) { bb_result r=bb_run(e,s,END,1000); if(r!=BB_STOP){fprintf(stderr,"unexpected result: %s\n",bb_result_name(r)); abort();} }
static void word(FILE *f, long off, uint32_t *w) { assert(!fseek(f,off,SEEK_SET) && fread(w,4,1,f)==1); }
static void native_flags(unsigned kind, uint64_t a, uint64_t *v, uint64_t *f) {
    switch (kind) {
    case 0: __asm__ volatile("adds %0, %2, #1\n\tmrs %1, nzcv":"=&r"(*v),"=&r"(*f):"r"(a):"cc"); break;
    case 1: __asm__ volatile("subs %0, %2, #1\n\tmrs %1, nzcv":"=&r"(*v),"=&r"(*f):"r"(a):"cc"); break;
    case 2: __asm__ volatile("adds %w0, %w2, #1\n\tmrs %1, nzcv":"=&r"(*v),"=&r"(*f):"r"(a):"cc"); break;
    default: __asm__ volatile("subs %w0, %w2, #1\n\tmrs %1, nzcv":"=&r"(*v),"=&r"(*f):"r"(a):"cc"); break;
    }
}
int main(int argc, char **argv) {
    assert(argc==2);
    { uint32_t p[]={0xd2824680,0xf2b579a0,0x91001c00,0xd65f03c0};
      bb_engine *e=make(p,4,4); bb_state s=start(e,0); for(unsigned i=1;i<30;++i)s.x[i]=UINT64_C(0xabc000)+i; s.nzcv=0xa0000000;
      uint64_t saved_sp=s.sp; run(e,&s);
      oop_ctx *old=oop_create(p,sizeof(p),sizeof(p),0); assert(old && oop_translate(old)); uint64_t expected; assert(oop_run(old,&expected));
      assert(s.x[0]==expected && s.sp==saved_sp && s.nzcv==0xa0000000); for(unsigned i=1;i<30;++i)assert(s.x[i]==UINT64_C(0xabc000)+i);
      bb_stats st=bb_get_stats(e); assert(st.native_blocks && st.interpreted_instructions); oop_destroy(old); bb_destroy(e); }
    { uint32_t p[]={0xb1000420,0xd65f03c0}; bb_engine *e=make(p,2,4); bb_state s=start(e,0); s.x[1]=UINT64_MAX;
      uint64_t val,flags,src=UINT64_MAX; __asm__ volatile("adds %0, %2, #1\n\tmrs %1, nzcv":"=&r"(val),"=&r"(flags):"r"(src):"cc");
      run(e,&s); assert(s.x[0]==val && s.nzcv==(flags&0xf0000000)); bb_destroy(e); }
    { uint32_t p[]={0x92800002,0x72a24682,0x91000440,0x910043ff,0xd10043ff,0xd65f03c0};
      bb_engine *e=make(p,6,4); bb_state s=start(e,0); uint64_t sp=s.sp; run(e,&s);
      assert(s.x[2]==UINT64_C(0x1234ffff) && s.x[0]==UINT64_C(0x12350000) && s.sp==sp); bb_destroy(e); }
    { uint32_t ops[]={0xb1000420,0xf1000420,0x31000420,0x71000420};
      uint64_t cases[]={0,1,2,UINT32_MAX,UINT64_MAX,UINT64_C(0x7fffffff),UINT64_C(0x80000000),UINT64_C(0x7fffffffffffffff),UINT64_C(0x8000000000000000)};
      for(unsigned k=0;k<4;++k) { uint32_t p[]={ops[k],0xd65f03c0}; bb_engine *e=make(p,2,2);
        for(unsigned i=0;i<sizeof(cases)/sizeof(cases[0]);++i) { bb_state s=start(e,0); s.x[1]=cases[i]; uint64_t v,nzcv; native_flags(k,cases[i],&v,&nzcv);
          run(e,&s); assert(s.x[0]==v && s.nzcv==(nzcv&0xf0000000)); }
        bb_destroy(e); } }
    { uint32_t p[]={0x52800000,0x7100001f,0x54000060,0x52800120,0x14000002,0x528000e0,0xd65f03c0};
      bb_engine *e=make(p,7,4); bb_state s=start(e,0); run(e,&s); assert(s.x[0]==7 && (s.nzcv&0x40000000)); bb_destroy(e); }
    { uint32_t p[]={0x52800000,0x34000060,0x52800120,0x14000002,0x528000e0,0xd65f03c0};
      bb_engine *e=make(p,6,4); bb_state s=start(e,0); run(e,&s); assert(s.x[0]==7); bb_destroy(e); }
    { uint32_t p[]={0x52800000,0x36000060,0x52800120,0x14000002,0x528000e0,0xd65f03c0};
      bb_engine *e=make(p,6,4); bb_state s=start(e,0); run(e,&s); assert(s.x[0]==7); bb_destroy(e); }
    { uint32_t p[]={adr(3,8),0xd61f0060,0x52800100,0xd65f03c0};
      bb_engine *e=make(p,4,4); bb_state s=start(e,0); run(e,&s); assert(s.x[0]==8); bb_destroy(e); }
    { uint32_t p[]={0xa9bf7bfd,adr(3,16),0xd63f0060,0xa8c17bfd,0xd65f03c0,0x528000e0,0xd65f03c0};
      bb_engine *e=make(p,7,4); bb_state s=start(e,0); uint64_t sp=s.sp; s.x[29]=0x1234; run(e,&s);
      assert(s.x[0]==7 && s.sp==sp && s.x[29]==0x1234 && s.x[30]==END); bb_destroy(e); }
    { uint32_t p[]={0xa9bf7bfd,0x94000004,0xa8c17bfd,0xd65f03c0,0xd503201f,
                    0xa9bf7bfd,0x94000004,0xa8c17bfd,0xd65f03c0,0xd503201f,0x52800120,0xd65f03c0};
      bb_engine *e=make(p,12,4); bb_state s=start(e,0); uint64_t sp=s.sp; run(e,&s);
      assert(s.x[0]==9 && s.sp==sp && s.x[30]==END); bb_destroy(e); }
    { uint32_t p[]={0x94000004,0xd65f03c0,0xd503201f,0xd503201f,0xaa1e03e0,0xd65f03c0};
      bb_engine *e=make(p,6,4); bb_state s=start(e,0);
      assert(bb_run(e,&s,bb_base(e)+4,20)==BB_STOP); assert(s.x[0]==bb_base(e)+4 && s.x[30]==bb_base(e)+4); bb_destroy(e); }
    { uint32_t p[]={adr(1,0),0xb9400020,0xd65f03c0}; bb_engine *e=make(p,3,4); bb_state s=start(e,0); run(e,&s);
      uint32_t actual=0; assert(s.x[0]==p[0]); assert(prototype_read(&actual,(void *)(uintptr_t)bb_base(e),4)==4 && actual==p[0]); bb_destroy(e); }
    { /* Native guest-PC address formation versus the checked one-step path. */
      int offsets[]={-1048576,-4097,-1,0,1,4095,1048575};
      for (unsigned page=0;page<2;++page) for (unsigned i=0;i<sizeof(offsets)/sizeof(offsets[0]);++i) {
        uint32_t p[]={page?adrp(7,offsets[i]):adr(7,offsets[i]),adr(31,-1),0xd65f03c0};
        bb_engine *e=make(p,3,4); bb_state a=start(e,0), b; a.x[7]=123; a.nzcv=0xb0000000; b=a;
        run(e,&a); bb_stats stats=bb_get_stats(e);
        assert(stats.native_blocks==1 && stats.interpreted_instructions==1);
        bb_result r; do { r=bb_run(e,&b,END,1); assert(r==BB_BUDGET || r==BB_STOP); } while(r==BB_BUDGET);
        uint64_t pc=bb_base(e), expected=page?(pc&~UINT64_C(4095))+(uint64_t)((int64_t)offsets[i]*4096):pc+(uint64_t)(int64_t)offsets[i];
        assert(a.x[7]==expected && !memcmp(&a,&b,sizeof(a)) && a.nzcv==0xb0000000);
        uint32_t original[3]; assert(bb_read(e,pc,original,sizeof(original)) && !memcmp(original,p,sizeof(p)));
        bb_destroy(e);
      } }
    { /* More than one address in a block, including an ADRP across a 4 KiB boundary. */
      uint32_t p[]={0xd503201f,adr(1,-7),adrp(2,1),adr(3,3),0xd65f03c0};
      bb_engine *e=make(p,5,4); uint64_t pc=bb_base(e)+PAGE-8;
      assert(bb_protect(e,PAGE,PAGE,BB_R|BB_W|BB_X)); assert(bb_write(e,pc,p,sizeof(p)));
      bb_state s=start(e,PAGE-8); run(e,&s);
      assert(s.x[1]==pc+4-7 && s.x[2]==((pc+8)&~UINT64_C(4095))+4096 && s.x[3]==pc+15);
      bb_stats stats=bb_get_stats(e); assert(stats.native_blocks==1 && stats.native_instructions==4 && stats.interpreted_instructions==1);
      bb_destroy(e); }
    { uint32_t p[]={0x58000080,0xd65f03c0,0xd503201f,0xd503201f,0,0}; bb_engine *e=make(p,6,4);
      uint64_t reloc=bb_base(e)+0x1234; assert(bb_write(e,bb_base(e)+16,&reloc,8));
      assert(bb_protect(e,0,PAGE,BB_R|BB_X)); bb_state s=start(e,0); run(e,&s); assert(s.x[0]==reloc);
      uint64_t readback=0; assert(prototype_read(&readback,(void *)(uintptr_t)(bb_base(e)+16),8)==8 && readback==reloc); bb_destroy(e); }
    { uint32_t p[]={0x11223344,0x55667788,0x58ffffc0,0xd65f03c0}; bb_engine *e=make(p,4,4);
      bb_state s=start(e,8); run(e,&s); assert(s.x[0]==UINT64_C(0x5566778811223344)); bb_destroy(e); }
    { uint32_t p[]={0xb9000041,0xd65f03c0}; bb_engine *e=make(p,2,2); uint32_t f[]={0x52800540,0xd65f03c0};
      uint64_t dst=bb_base(e)+512; assert(bb_write(e,dst,f,sizeof(f))); bb_state s=start(e,512); run(e,&s); assert(s.x[0]==42);
      s=start(e,0); s.x[1]=0x52800560; s.x[2]=dst; run(e,&s); s=start(e,512); run(e,&s); assert(s.x[0]==43);
      uint32_t via=0; assert(prototype_read(&via,(void *)(uintptr_t)dst,4)==4 && via==0x52800560);
      assert(bb_get_stats(e).invalidations>0); assert(bb_protect(e,0,PAGE,BB_R|BB_X)); assert(!bb_write(e,dst,f,4));
      s=start(e,0); s.x[1]=0x52800540; s.x[2]=dst; assert(bb_run(e,&s,END,10)==BB_MEMORY && s.pc==bb_base(e)); bb_destroy(e); }
    { uint32_t p[]={0xa9bf7bfd,0xa8c17bfd,0xd65f03c0}; bb_engine *e=make(p,3,4); bb_state s=start(e,0);
      s.sp=bb_base(e)+PAGE*2+8; uint64_t old=s.sp; run(e,&s); assert(s.sp==old);
      assert(bb_protect(e,PAGE,PAGE,BB_R)); s=start(e,0); s.sp=old; assert(bb_run(e,&s,END,10)==BB_MEMORY && s.sp==old && s.pc==bb_base(e));
      assert(!bb_read(e,bb_base(e)+PAGE*4-4,&old,8)); bb_destroy(e); }
    { uint32_t p[]={0xd65f03c0}; bb_engine *e=make(p,1,2); unsigned char b[8];
      assert(bb_protect(e,PAGE,PAGE,BB_W)); assert(!bb_read(e,bb_base(e)+PAGE-4,b,8));
      assert(bb_protect(e,PAGE,PAGE,BB_R|BB_W)); assert(bb_read(e,bb_base(e)+PAGE-4,b,8)); bb_destroy(e); }
    { uint32_t p[]={0xf9400020,0xd65f03c0}; bb_engine *e=make(p,2,2); bb_state s=start(e,0); s.x[1]=1;
      assert(bb_run(e,&s,END,10)==BB_MEMORY && s.pc==bb_base(e)); s.pc=bb_base(e)+2; assert(bb_run(e,&s,END,10)==BB_ALIGNMENT); bb_destroy(e); }
    { uint32_t p[]={0xd61f0060}; bb_engine *e=make(p,1,2); bb_state s=start(e,0); s.x[3]=0x1000;
      assert(bb_run(e,&s,END,10)==BB_MEMORY && s.pc==0x1000); bb_destroy(e); }
    { uint32_t p[]={0xd4000001}; bb_engine *e=make(p,1,2); bb_state s=start(e,0); assert(bb_run(e,&s,END,10)==BB_UNSUPPORTED && s.pc==bb_base(e)); bb_destroy(e); }
    { uint32_t p[]={0x14000000}; bb_engine *e=make(p,1,2); bb_state s=start(e,0); assert(bb_run(e,&s,END,19)==BB_BUDGET && s.pc==bb_base(e)); bb_destroy(e); }
    { uint32_t p[]={movz(0,1),0x11000400,0x11000400,0xd65f03c0}; bb_engine *e=make(p,4,2); bb_state s=start(e,0);
      assert(bb_run(e,&s,END,1)==BB_BUDGET && s.x[0]==1 && s.pc==bb_base(e)+4); run(e,&s); assert(s.x[0]==3); bb_destroy(e); }
    { uint32_t p[]={movz(0,1),0x11000400,0xd65f03c0}; bb_engine *e=make(p,3,2); bb_state s=start(e,0);
      assert(bb_run(e,&s,bb_base(e)+4,20)==BB_STOP && s.x[0]==1 && s.pc==bb_base(e)+4); bb_destroy(e); }
    { uint32_t p[]={movz(0,1),0xd65f03c0, movz(0,2),0xd65f03c0, movz(0,3),0xd65f03c0}; bb_engine *e=make(p,6,2);
      for(unsigned i=0;i<3;++i) { bb_state s=start(e,i*8); run(e,&s); assert(s.x[0]==i+1); } assert(bb_get_stats(e).evictions>0); bb_destroy(e); }
    { /* Differential: each native block versus one checked interpreter step at a time. */
      uint32_t p[]={movz(0,1),0x11000400,0xd65f03c0}; bb_engine *e=make(p,3,4); uint32_t seed=0x9e3779b9;
      for(unsigned i=0;i<256;++i) {
        seed=seed*1664525u+1013904223u; unsigned rd=(seed>>16)%30, rn=(seed>>21)&31;
        p[0]=((seed&1)?0xd2800000u:0x52800000u)|(((seed>>2)&0xffff)<<5)|rd;
        p[1]=((seed&2)?0x91000000u:0x11000000u)|((seed&4)?0x40000000u:0)|(((seed>>5)&0xfff)<<10)|(rn<<5)|rd;
        assert(bb_write(e,bb_base(e),p,sizeof(p))); bb_state a=start(e,0), b;
        for(unsigned j=0;j<31;++j) a.x[j]=(UINT64_C(0xfedcba9876543210)^seed)+j; a.x[30]=END; a.nzcv=0x90000000; b=a;
        run(e,&a); bb_result r; do { r=bb_run(e,&b,END,1); assert(r==BB_BUDGET || r==BB_STOP); } while(r==BB_BUDGET);
        assert(!memcmp(&a,&b,sizeof(a)));
      } bb_destroy(e); }
    FILE *f=fopen(argv[1],"rb"); assert(f);
    { uint32_t p[3]; for(int i=0;i<3;++i) word(f,0x13a50b8+i*4,&p[i]); assert(p[0]==0xd0007c80 && p[1]==0x91209800 && p[2]==0xd65f03c0);
      bb_engine *e=make(p,3,4); bb_state s=start(e,0); uint64_t pc=s.pc; run(e,&s);
      uint64_t imm=(((p[0]>>5)&0x7ffff)<<2)|((p[0]>>29)&3); int64_t d=(int64_t)(imm^(1u<<20))-(1u<<20);
      assert(s.x[0]==(pc&~UINT64_C(4095))+(uint64_t)(d*4096)+((p[1]>>10)&0xfff)); bb_destroy(e); }
    { uint32_t p[3]; word(f,0x13a50f8,&p[0]); assert(p[0]==0xd53bd059); p[1]=0xaa1903e0; p[2]=0xd65f03c0;
      bb_engine *e=make(p,3,4); bb_state s=start(e,0); s.tpidr_el0=UINT64_C(0x12345678); run(e,&s); assert(s.x[0]==s.tpidr_el0 && s.x[25]==s.tpidr_el0); bb_destroy(e); }
    { /* Execute the real ELF leaf in a copy of its complete executable LOAD. */
      size_t n=0x26ca520; unsigned char *image=malloc(n); assert(image && !fseek(f,0,SEEK_SET) && fread(image,1,n,f)==n);
      bb_engine *e=bb_create(image,n,4); assert(e && bb_protect(e,0,(n+PAGE-1)&~(size_t)(PAGE-1),BB_R|BB_X));
      bb_state s=start(e,0x13a50b8); run(e,&s);
      /* InitializeRequest::getRequestID returns a guest image pointer, not a cache address. */
      assert(s.x[0]==bb_base(e)+0x2337826 && s.pc==END && s.x[30]==END);
      bb_stats stats=bb_get_stats(e); assert(stats.native_blocks==1 && stats.native_instructions==2 && stats.interpreted_instructions==1);
      unsigned char got[16], via[16]; assert(bb_read(e,s.x[0],got,sizeof(got)));
      assert(!memcmp(got,image+(size_t)(s.x[0]-bb_base(e)),sizeof(got)));
      assert(prototype_read(via,(void *)(uintptr_t)s.x[0],sizeof(via))==sizeof(via) && !memcmp(via,got,sizeof(got)));
      uintptr_t leaf=bb_base(e)+0x13a50b8;
      assert(bb_read(e,leaf,got,12) && !memcmp(got,image+0x13a50b8,12));
      assert(prototype_read(via,(void *)leaf,12)==12 && !memcmp(via,got,12));
      assert(bb_protect(e,0x13a5000,PAGE,BB_R|BB_W|BB_X));
      s=start(e,0x13a50b8); run(e,&s); /* protect invalidated the earlier block; prime it again. */
      stats=bb_get_stats(e);
      uint32_t changed=0x91209c00; /* ADD immediate +1 in this private test mapping. */
      assert(bb_write(e,leaf+4,&changed,4) && bb_get_stats(e).invalidations>stats.invalidations);
      s=start(e,0x13a50b8); run(e,&s); assert(s.x[0]==bb_base(e)+0x2337827);
      uint32_t unsupported=0xd4000001;
      assert(bb_write(e,leaf,&unsupported,4)); s=start(e,0x13a50b8);
      assert(bb_run(e,&s,END,100)==BB_UNSUPPORTED && s.pc==leaf);
      assert(bb_write(e,leaf,image+0x13a50b8,12));
      assert(!memcmp((void *)(uintptr_t)bb_base(e),image,n));
      puts("InitializeRequest::getRequestID: guest pointer and LR/PC preserved; native blocks=1, checked RET=1; controlled invalidation and unsupported instruction passed");
      bb_destroy(e); free(image); }
    fclose(f); puts("block engine: native ADR/ADRP, cache, checked fallback, control flow, memory, invalidation and APK sequences passed");
}
