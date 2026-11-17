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
/* Test all condition codes with actual ARM instructions and caller-supplied NZCV. */
#define NATIVE_SELECT(C, R) do { \
    __asm__ volatile("msr nzcv, %6\n\t" \
        "csel " R "0, " R "4, " R "5, " #C "\n\t" \
        "csinc " R "1, " R "4, " R "5, " #C "\n\t" \
        "csinv " R "2, " R "4, " R "5, " #C "\n\t" \
        "csneg " R "3, " R "4, " R "5, " #C \
        : "=&r"(out[0]), "=&r"(out[1]), "=&r"(out[2]), "=&r"(out[3]) \
        : "r"(a), "r"(b), "r"(nzcv) : "cc"); \
} while (0)
#define SELECT_CASE(I,C) case I: if (wide) NATIVE_SELECT(C,"%"); else NATIVE_SELECT(C,"%w"); break
static void native_select(unsigned cond, bool wide, uint64_t a, uint64_t b, uint64_t nzcv, uint64_t out[4]) {
    switch (cond) {
    SELECT_CASE(0,eq); SELECT_CASE(1,ne); SELECT_CASE(2,hs); SELECT_CASE(3,lo);
    SELECT_CASE(4,mi); SELECT_CASE(5,pl); SELECT_CASE(6,vs); SELECT_CASE(7,vc);
    SELECT_CASE(8,hi); SELECT_CASE(9,ls); SELECT_CASE(10,ge); SELECT_CASE(11,lt);
    SELECT_CASE(12,gt); SELECT_CASE(13,le); SELECT_CASE(14,al); SELECT_CASE(15,nv);
    }
}
#undef SELECT_CASE
#undef NATIVE_SELECT
int main(int argc, char **argv) {
    assert(argc==2);
    { /* Real OpenSSL software SHA-256 instructions versus native ARM64. */
      uint32_t p[]={0x5ac00844,0x13981b10,0x4ad83b06,0x0a380353,0xd65f03c0};
      uint32_t inputs[]={0,1,0x12345678,0x80000000,0xffffffff}; bb_engine *e=make(p,5,4);
      for (size_t i=0;i<sizeof(inputs)/sizeof(inputs[0]);i++) {
        uint32_t x=inputs[i], y=~x, a,b,c,d;
        __asm__ volatile("rev %w0, %w4\n\tror %w1, %w5, #6\n\teor %w2, %w5, %w5, ror #14\n\tbic %w3, %w6, %w5"
            : "=&r"(a),"=&r"(b),"=&r"(c),"=&r"(d) : "r"(x),"r"(y),"r"(x));
        bb_state s=start(e,0); s.x[2]=x; s.x[24]=y; s.x[26]=x; run(e,&s);
        assert(s.x[4]==a && s.x[16]==b && s.x[6]==c && s.x[19]==d);
      } bb_destroy(e); }
    { /* Game initializer DUP and destructor's UXTW-scaled ADD. */
      uint32_t p[]={0x4e080c20,0x8b334d20,0xd65f03c0}; uint64_t vector[2], native;
      uint64_t input=UINT64_C(0x12345678abcdef01), base=UINT64_C(0x100000000), index=UINT64_C(0xffffffff80000001);
      __asm__ volatile("dup v0.2d, %2\n\tstr q0, [%1]\n\tadd %0, %3, %w4, uxtw #3"
          : "=&r"(native) : "r"(vector),"r"(input),"r"(base),"r"(index) : "v0","memory");
      bb_engine *e=make(p,3,4); bb_state s=start(e,0);
      s.x[1]=input; s.x[9]=base; s.x[19]=index; run(e,&s);
      assert(!memcmp(s.v[0],vector,16) && s.x[0]==native); bb_destroy(e); }
    { /* Cocos D pre-store, zero, and post-load against native ARM64. */
      uint32_t p[]={0xfc1e0fe8,0x2f00e408,0xfc4207e8,0xd65f03c0};
      uint64_t input[2]={UINT64_C(0x123456789abcdef0),UINT64_MAX}, host[16]={0}, output[2], *cursor=host+8;
      __asm__ volatile("ldr q8, [%2]\n\tstr d8, [%0, #-32]!\n\tmovi d8, #0\n\tldr d8, [%0], #32\n\tstr q8, [%1]"
          : "+r"(cursor) : "r"(output),"r"(input) : "v8","memory");
      bb_engine *e=make(p,4,4); bb_state s=start(e,0); uint64_t sp=bb_base(e)+PAGE+64;
      s.sp=sp; memcpy(s.v[8],input,16); run(e,&s);
      uint64_t saved; assert(bb_read(e,sp-32,&saved,8) && saved==host[4]);
      assert(s.sp==sp && !memcmp(s.v[8],output,16)); bb_destroy(e); }
    { /* Real game UMULL / shift / MSUB seed arithmetic against native. */
      uint32_t p[]={0x9ba87c08,0xd367fd08,0x1b098108,0xd65f03c0};
      uint32_t cases[]={0,1,252,253,254,0x12345678,0x7fffffff};
      bb_engine *e=make(p,4,4);
      for (size_t i=0;i<sizeof(cases)/sizeof(cases[0]);i++) {
        uint32_t input=cases[i], divisor=253, native; uint64_t tmp, factor=0x81848da9;
        __asm__ volatile("umull %0, %w2, %w3\n\tlsr %0, %0, #39\n\tmsub %w1, %w0, %w4, %w2"
            : "=&r"(tmp),"=&r"(native) : "r"(input),"r"(factor),"r"(divisor));
        bb_state s=start(e,0); s.x[0]=input; s.x[8]=factor; s.x[9]=divisor; run(e,&s);
        assert(s.x[8]==native);
      } bb_destroy(e); }
    { /* Real destructor's STR X post-index, including writeback. */
      uint32_t p[]={0xf8018688,0xd65f03c0}; uint64_t host[8]={0}, value=UINT64_C(0x123456789abcdef0), actual;
      uint64_t *cursor=host;
      __asm__ volatile("str %1, [%0], #24" : "+r"(cursor) : "r"(value) : "memory");
      bb_engine *e=make(p,2,4); bb_state s=start(e,0); uint64_t addr=bb_base(e)+PAGE;
      s.x[20]=addr; s.x[8]=value; run(e,&s);
      assert(bb_read(e,addr,&actual,8) && actual==host[0] && s.x[20]==addr+(uintptr_t)cursor-(uintptr_t)host);
      assert(bb_protect(e,PAGE,PAGE,BB_R)); s=start(e,0); s.x[20]=addr; s.x[8]=value;
      assert(bb_run(e,&s,END,10)==BB_MEMORY && s.x[20]==addr); bb_destroy(e); }
    { /* Cocos scalar moves, immediate, and vector copies vs real ARM64. */
      uint32_t p[]={0x1e270020,0x4ea01c08,0x1e251002,0x4ea21c43,0xd65f03c0};
      uint64_t expected[8]={0}; uint32_t input=0x81234567;
      __asm__ volatile("fmov s0, %w1\n\tmov v8.16b, v0.16b\n\tfmov s2, #12.0\n\tmov v3.16b, v2.16b\n\t"
          "str q0, [%0]\n\tstr q8, [%0, #16]\n\tstr q2, [%0, #32]\n\tstr q3, [%0, #48]"
          :: "r"(expected), "r"(input) : "v0","v2","v3","v8","memory");
      bb_engine *e=make(p,5,4); bb_state s=start(e,0); s.x[1]=input;
      for (int i=0;i<32;i++) s.v[i][0]=s.v[i][1]=UINT64_MAX;
      run(e,&s); assert(!memcmp(s.v[0],expected,16) && !memcmp(s.v[8],expected+2,16));
      assert(!memcmp(s.v[2],expected+4,16) && !memcmp(s.v[3],expected+6,16)); bb_destroy(e); }
    { /* Cocos saves D pairs, restores them, and writes S and unscaled D. */
      uint32_t p[]={0x6d0123e9,0x6d4123e9,0x2d032269,0xfc00c000,0xd65f03c0};
      uint64_t vec[4]={UINT64_C(0x123456789abcdef0),UINT64_C(0x123),UINT64_C(0xfedcba9876543210),UINT64_C(0x456)};
      unsigned char expected_stack[64]={0}, expected_obj[64]={0}, expected_out[64]={0}, got[64];
      __asm__ volatile("ldr q9, [%2]\n\tldr q8, [%2, #16]\n\tstp d9, d8, [%0, #16]\n\tldp d9, d8, [%0, #16]\n\t"
          "stp s9, s8, [%1, #24]"
          :: "r"(expected_stack),"r"(expected_obj),"r"(vec) : "v8","v9","memory");
      /* Set D0 explicitly on both paths for the unscaled store. */
      __asm__ volatile("fmov d0, %0\n\tstur d0, [%1, #12]" :: "r"(vec[0]),"r"(expected_out) : "v0","memory");
      bb_engine *e=make(p,5,4); bb_state s=start(e,0); uint64_t base=bb_base(e)+PAGE;
      s.sp=base; s.x[19]=base+128; s.x[0]=base+256;
      memcpy(s.v[9],vec,16); memcpy(s.v[8],vec+2,16); s.v[0][0]=vec[0]; run(e,&s);
      assert(bb_read(e,base,got,64) && !memcmp(got,expected_stack,64));
      assert(bb_read(e,base+128,got,64) && !memcmp(got,expected_obj,64));
      assert(bb_read(e,base+256,got,64) && !memcmp(got,expected_out,64));
      assert(s.v[9][0]==vec[0] && !s.v[9][1] && s.v[8][0]==vec[2] && !s.v[8][1]); bb_destroy(e); }
    { /* Real vtable negative-offset load. */
      uint32_t p[]={0xf85e8108,0xd65f03c0};
      uint64_t host[8]={0}, native, value=UINT64_C(0xaabbccddeeff0011);
      host[2]=value; uint64_t *point=&host[5];
      __asm__ volatile("ldur %0, [%1, #-24]" : "=r"(native) : "r"(point) : "memory");
      bb_engine *e=make(p,2,4); bb_state s=start(e,0);
      uint64_t base=bb_base(e)+PAGE; assert(bb_write(e,base+16,&value,8));
      s.x[8]=base+40; run(e,&s); assert(s.x[8]==native); bb_destroy(e); }
    { /* Actual ios_base SIMD pointer pair and post-indexed vector store. */
      uint32_t p[]={0x9e670100,0x4e181d20,0x3c808400,0xd65f03c0};
      uint64_t expected[2]={0}, actual[2], *cursor=expected;
      uint64_t lo=UINT64_C(0x123456789abcdef0), hi=UINT64_C(0xfedcba9876543210);
      __asm__ volatile("fmov d0, %1\n\tins v0.d[1], %2\n\tstr q0, [%0], #8"
          : "+r"(cursor) : "r"(lo), "r"(hi) : "v0", "memory");
      bb_engine *e=make(p,4,4); bb_state s=start(e,0);
      uint64_t base=bb_base(e)+PAGE; s.x[0]=base; s.x[8]=lo; s.x[9]=hi;
      s.v[0][1]=UINT64_MAX; run(e,&s);
      assert(bb_read(e,base,actual,sizeof(actual)) && !memcmp(actual,expected,sizeof(actual)));
      assert(s.x[0]==base+(uintptr_t)cursor-(uintptr_t)expected); bb_destroy(e); }
    { /* libc++'s W pair store, followed by a W pair load. */
      uint32_t p[]={0x29047c09,0x29442c0a,0xd65f03c0};
      bb_engine *e=make(p,3,4); bb_state s=start(e,0);
      uint32_t host[16]={0}, actual[2]; unsigned input=0x89abcdef, first, second;
      __asm__ volatile("stp %w3, wzr, [%2, #32]\n\tldp %w0, %w1, [%2, #32]"
          : "=&r"(first), "=&r"(second) : "r"(host), "r"(input) : "memory");
      s.x[0]=bb_base(e)+PAGE; s.x[9]=UINT64_C(0xffffffff00000000)|input;
      s.x[10]=s.x[11]=UINT64_MAX; run(e,&s);
      assert(bb_read(e,s.x[0]+32,actual,sizeof(actual)));
      assert(!memcmp(actual,host+8,sizeof(actual)) && s.x[10]==first && s.x[11]==second);
      bb_destroy(e); }
    { /* All condition codes and NZCV values, both widths and all four forms. */
      for (unsigned wide=0;wide<2;wide++) for (unsigned cond=0;cond<16;cond++) {
        uint32_t p[5];
        for (unsigned op=0;op<4;op++) p[op]=0x1a820020u | (wide<<31) | ((op>>1)<<30) | ((op&1)<<10) | (cond<<12) | (8+op);
        p[4]=0xd65f03c0; bb_engine *e=make(p,5,4);
        for (unsigned f=0;f<16;f++) {
          uint64_t a=UINT64_C(0x8123456787654321), b=UINT64_C(0xfedcba9876543210), nzcv=(uint64_t)f<<28, native[4];
          native_select(cond,wide,a,b,nzcv,native);
          bb_state s=start(e,0); s.x[1]=a; s.x[2]=b; s.nzcv=nzcv; run(e,&s);
          for (unsigned op=0;op<4;op++) assert(s.x[8+op]==native[op]);
          assert(s.nzcv==nzcv);
        }
        bb_destroy(e);
      }
      uint32_t p[]={0x1a9f17e9,0xd65f03c0}; bb_engine *e=make(p,2,4);
      for (unsigned z=0;z<2;z++) { bb_state s=start(e,0); s.nzcv=(uint64_t)z<<30; run(e,&s); assert(s.x[9]==z); }
      bb_destroy(e); }
    { /* Real libc++ logical immediate, compared with native ARM64. */
      uint32_t p[]={0x12000009,0xd65f03c0}; bb_engine *e=make(p,2,4);
      for (unsigned i=0;i<4;i++) { bb_state s=start(e,0); unsigned native;
        __asm__ volatile("and %w0, %w1, #1" : "=r"(native) : "r"(i));
        s.x[0]=i; run(e,&s); assert(s.x[9]==native); }
      bb_destroy(e); }
    { /* Scalar FP load zeroes the upper lane and stores the loaded bits. */
      uint32_t p[]={0xfd400100,0xfd000900,0xd65f03c0};
      bb_engine *e=make(p,3,4); bb_state s=start(e,0);
      uint64_t input=UINT64_C(0x0123456789abcdef), output=0;
      s.x[8]=bb_base(e)+PAGE; s.v[0][1]=UINT64_MAX;
      assert(bb_write(e,s.x[8],&input,8)); run(e,&s);
      assert(bb_read(e,s.x[8]+16,&output,8));
      assert(output==input && s.v[0][0]==input && s.v[0][1]==0); bb_destroy(e); }
    { /* Halfword immediate access used by libc++ locale facets. */
      uint32_t p[]={0x7900210a,0x7940210b,0xd65f03c0};
      bb_engine *e=make(p,3,4); bb_state s=start(e,0);
      uint16_t host[16]={0}, actual; unsigned input=0x12c2e, native;
      __asm__ volatile("strh %w2, [%1, #16]\n\tldrh %w0, [%1, #16]"
          : "=&r"(native) : "r"(host), "r"(input) : "memory");
      s.x[8]=bb_base(e)+PAGE; s.x[10]=input; run(e,&s);
      assert(bb_read(e,s.x[8]+16,&actual,2));
      assert(actual==host[8] && s.x[11]==native); bb_destroy(e); }
    { /* libc++ guard release: compare byte release/acquire with ARM64. */
      uint32_t p[]={0x089ffc01,0x08dffc02,0xd65f03c0};
      bb_engine *e=make(p,3,4); bb_state s=start(e,0);
      uint8_t native_byte=0, actual=0; unsigned native_value; unsigned input=0x15a;
      __asm__ volatile("stlrb %w2, [%1]\n\tldarb %w0, [%1]"
          : "=&r"(native_value) : "r"(&native_byte), "r"(input) : "memory");
      s.x[0]=bb_base(e)+PAGE; s.x[1]=input; run(e,&s);
      assert(bb_read(e,s.x[0],&actual,1));
      assert(actual==native_byte && s.x[2]==native_value); bb_destroy(e); }
    { /* The indexed 64-bit load/store pair used by libc++ locale setup. */
      uint32_t p[]={0xf8757900,0xf8357916,0xd65f03c0};
      bb_engine *e=make(p,3,4); bb_state s=start(e,0);
      uint64_t values[4]={1,2,UINT64_C(0x123456789abcdef0),4}, native;
      uint64_t index=2, replacement=UINT64_C(0xfedcba9876543210);
      __asm__ volatile("ldr %0, [%1, %2, lsl #3]\n\tstr %3, [%1, %2, lsl #3]"
          : "=&r"(native) : "r"(values), "r"(index), "r"(replacement) : "memory");
      uint64_t initial=UINT64_C(0x123456789abcdef0), result;
      uint64_t addr=bb_base(e)+PAGE; assert(bb_write(e,addr+16,&initial,8));
      s.x[8]=addr; s.x[21]=index; s.x[22]=replacement; run(e,&s);
      assert(bb_read(e,addr+16,&result,8));
      assert(s.x[0]==native && result==values[2]); bb_destroy(e); }
    { uint32_t p[]={0xd2824680,0xf2b579a0,0x91001c00,0xd65f03c0};
      bb_engine *e=make(p,4,4); bb_state s=start(e,0); for(unsigned i=1;i<30;++i)s.x[i]=UINT64_C(0xabc000)+i; s.nzcv=0xa0000000;
      uint64_t saved_sp=s.sp; run(e,&s);
      oop_ctx *old=oop_create(p,sizeof(p),sizeof(p),0); assert(old && oop_translate(old)); uint64_t expected; assert(oop_run(old,&expected));
      assert(s.x[0]==expected && s.sp==saved_sp && s.nzcv==0xa0000000); for(unsigned i=1;i<30;++i)assert(s.x[i]==UINT64_C(0xabc000)+i);
      bb_stats st=bb_get_stats(e); assert(st.native_blocks && !st.interpreted_instructions); oop_destroy(old); bb_destroy(e); }
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
        assert(stats.native_blocks==2 && stats.interpreted_instructions==0);
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
      bb_stats stats=bb_get_stats(e); assert(stats.native_blocks==2 && stats.native_instructions==5 && stats.interpreted_instructions==0);
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
    { /* Offset STP/LDP: compare real ARM64 memory and registers. */
      uint32_t p[]={0xa9010440,0xa9411043,0xd65f03c0}; /* stp x0,x1,[x2,#16]; ldp x3,x4,[x2,#16] */
      bb_engine *e=make(p,3,4); bb_state s=start(e,0);
      uint64_t a=UINT64_C(0x123456789abcdef0),b=UINT64_C(0xfedcba9876543210),expected[4]={0},actual[2];
      __asm__ volatile("stp %1, %2, [%0, #16]" :: "r"(expected),"r"(a),"r"(b) : "memory");
      s.x[0]=a; s.x[1]=b; s.x[2]=bb_base(e)+PAGE; s.nzcv=0xa0000000;
      run(e,&s); assert(bb_read(e,s.x[2]+16,actual,sizeof(actual)));
      assert(actual[0]==expected[2] && actual[1]==expected[3] && s.x[3]==a && s.x[4]==b && s.nzcv==0xa0000000);
      assert(bb_protect(e,PAGE,PAGE,BB_R)); s=start(e,0); s.x[2]=bb_base(e)+PAGE;
      assert(bb_run(e,&s,END,20)==BB_MEMORY && s.pc==bb_base(e)); bb_destroy(e); }
    { /* Indexed STR/LDR: native comparison and failed-access writeback. */
      uint32_t p[]={0xf81f0c40,0xf8410441,0xd65f03c0};
      uint64_t native_mem[4]={0}, *cursor=native_mem+2, value=UINT64_C(0x18f23456789abcde), native_value;
      __asm__ volatile("str %2, [%0, #-16]!\n\tldr %1, [%0], #16" : "+r"(cursor),"=&r"(native_value) : "r"(value) : "memory");
      bb_engine *e=make(p,3,4); bb_state s=start(e,0); s.x[0]=value; s.x[2]=bb_base(e)+PAGE+16;
      run(e,&s); uint64_t out=0; assert(bb_read(e,bb_base(e)+PAGE,&out,8));
      assert(s.x[1]==native_value && out==native_mem[0] && s.x[2]==bb_base(e)+PAGE+16 && cursor==native_mem+2);
      assert(bb_protect(e,PAGE,PAGE,BB_R)); s=start(e,0); s.x[2]=bb_base(e)+PAGE+16;
      assert(bb_run(e,&s,END,10)==BB_MEMORY && s.x[2]==bb_base(e)+PAGE+16 && s.pc==bb_base(e)); bb_destroy(e); }
    { /* LDARB: native byte result, zero extension, and inaccessible source. */
      uint32_t p[]={0x08dffc20,0xd65f03c0}, native_value;
      unsigned char source=0xa5;
      __asm__ volatile("ldarb %w0, [%1]" : "=r"(native_value) : "r"(&source) : "memory");
      bb_engine *e=make(p,2,4); uint64_t ptr=bb_base(e)+PAGE;
      assert(bb_write(e,ptr,&source,1)); bb_state s=start(e,0); s.x[0]=UINT64_MAX; s.x[1]=ptr;
      run(e,&s); assert(s.x[0]==native_value && s.x[0]==0xa5);
      assert(bb_protect(e,PAGE,PAGE,0)); s=start(e,0); s.x[1]=ptr;
      assert(bb_run(e,&s,END,10)==BB_MEMORY && s.pc==bb_base(e)); bb_destroy(e); }
    { /* LDAR X: native acquire load and alignment faults. */
      uint32_t p[]={0xc8dffc20,0xd65f03c0}; uint64_t source=UINT64_C(0x123456789abcdef0),native;
      __asm__ volatile("ldar %0, [%1]" : "=r"(native) : "r"(&source) : "memory");
      bb_engine *e=make(p,2,4); uint64_t ptr=bb_base(e)+PAGE;
      assert(bb_write(e,ptr,&source,8)); bb_state s=start(e,0); s.x[1]=ptr; run(e,&s); assert(s.x[0]==native);
      s=start(e,0); s.x[1]=ptr+1; s.x[0]=99;
      assert(bb_run(e,&s,END,10)==BB_ALIGNMENT && s.pc==bb_base(e) && s.x[0]==99); bb_destroy(e); }
    { /* STLR X: native release store and alignment faults. */
      uint32_t p[]={0xc89ffc20,0xd65f03c0}; uint64_t native=0,value=UINT64_C(0xfedcba9876543210);
      __asm__ volatile("stlr %1, [%0]" :: "r"(&native),"r"(value) : "memory");
      bb_engine *e=make(p,2,4); uint64_t ptr=bb_base(e)+PAGE; bb_state s=start(e,0); s.x[0]=value; s.x[1]=ptr;
      run(e,&s); uint64_t actual; assert(bb_read(e,ptr,&actual,8) && actual==native);
      s=start(e,0); s.x[1]=ptr+1; assert(bb_run(e,&s,END,10)==BB_ALIGNMENT && s.pc==bb_base(e)); bb_destroy(e); }
    { /* Real libc++ LDAXR/STLXR loop and reservation invalidation. */
      uint32_t p[]={0x885ffd09,0x11000529,0x880afd09,0xd65f03c0};
      uint32_t native=42,loaded,status;
      do { __asm__ volatile("ldaxr %w0, [%2]\n\tadd %w0, %w0, #1\n\tstlxr %w1, %w0, [%2]"
          : "=&r"(loaded),"=&r"(status) : "r"(&native) : "memory"); } while(status);
      bb_engine *e=make(p,4,4); uint64_t ptr=bb_base(e)+PAGE; uint32_t initial=42;
      assert(bb_write(e,ptr,&initial,4)); bb_state s=start(e,0); s.x[8]=ptr; run(e,&s);
      uint32_t actual; assert(bb_read(e,ptr,&actual,4) && actual==native && s.x[9]==loaded && s.x[10]==0);
      assert(bb_write(e,ptr,&initial,4)); s=start(e,0); s.x[8]=ptr;
      assert(bb_run(e,&s,END,1)==BB_BUDGET && s.exclusive_valid);
      uint32_t other=7; assert(bb_write(e,ptr+8,&other,4)); run(e,&s);
      assert(bb_read(e,ptr,&actual,4) && actual==initial && s.x[10]==1 && !s.exclusive_valid);
      bb_destroy(e); }
    { /* Real libc++ 64-bit relaxed reference-count loop. */
      uint32_t p[]={0xc85f7d09,0x91000529,0xc80a7d09,0xd65f03c0};
      uint64_t native=UINT64_C(0x100000002),loaded; uint32_t status;
      do { __asm__ volatile("ldxr %0, [%2]\n\tadd %0, %0, #1\n\tstxr %w1, %0, [%2]"
          : "=&r"(loaded),"=&r"(status) : "r"(&native) : "memory"); } while(status);
      bb_engine *e=make(p,4,4); uint64_t ptr=bb_base(e)+PAGE, initial=UINT64_C(0x100000002);
      assert(bb_write(e,ptr,&initial,8)); bb_state s=start(e,0); s.x[8]=ptr; run(e,&s);
      uint64_t actual; assert(bb_read(e,ptr,&actual,8) && actual==native && s.x[9]==loaded && s.x[10]==0);
      bb_destroy(e); }
    { /* Byte stores and loads at nonzero unsigned offset. */
      uint32_t p[]={0x39000420,0x39400422,0xd65f03c0};
      uint8_t native[3]={0}; uint32_t value=0x1234abcd, loaded;
      __asm__ volatile("strb %w2, [%1, #1]\n\tldrb %w0, [%1, #1]" : "=&r"(loaded) : "r"(native),"r"(value) : "memory");
      bb_engine *e=make(p,3,4); bb_state s=start(e,0);
      s.x[0]=value; s.x[1]=bb_base(e)+PAGE; s.x[2]=UINT64_MAX; run(e,&s);
      uint8_t actual=0; assert(bb_read(e,s.x[1]+1,&actual,1) && actual==native[1] && s.x[2]==loaded);
      bb_destroy(e); }
    { /* Signed 32-bit load extends to 64 bits. */
      uint32_t p[]={0xb9800420,0xd65f03c0},data[2]={0,0x80000001}; uint64_t native;
      __asm__ volatile("ldrsw %0, [%1, #4]" : "=r"(native) : "r"(data) : "memory");
      bb_engine *e=make(p,2,4); uint64_t ptr=bb_base(e)+PAGE; assert(bb_write(e,ptr,data,sizeof(data)));
      bb_state s=start(e,0); s.x[1]=ptr; run(e,&s); assert(s.x[0]==native); bb_destroy(e); }
    { /* STRB post-index keeps writeback conditional on the store succeeding. */
      uint32_t p[]={0x38001420,0xd65f03c0}; uint8_t native[2]={0}, *cursor=native;
      uint32_t value=0x5a; __asm__ volatile("strb %w1, [%0], #1" : "+r"(cursor) : "r"(value) : "memory");
      bb_engine *e=make(p,2,4); bb_state s=start(e,0); s.x[0]=value; s.x[1]=bb_base(e)+PAGE;
      run(e,&s); uint8_t got=0; assert(bb_read(e,bb_base(e)+PAGE,&got,1));
      assert(got==native[0] && cursor==native+1 && s.x[1]==bb_base(e)+PAGE+1);
      assert(bb_protect(e,PAGE,PAGE,BB_R)); s=start(e,0); s.x[1]=bb_base(e)+PAGE;
      assert(bb_run(e,&s,END,3)==BB_MEMORY && s.x[1]==bb_base(e)+PAGE); bb_destroy(e); }
    { /* Register-offset byte store used for the string terminator. */
      uint32_t p[]={0x38236820,0xd65f03c0},value=0x5a; uint64_t index=3;
      uint8_t native[8]={0}; __asm__ volatile("strb %w1, [%0, %2]" :: "r"(native),"r"(value),"r"(index) : "memory");
      bb_engine *e=make(p,2,4); bb_state s=start(e,0); s.x[0]=value; s.x[1]=bb_base(e)+PAGE; s.x[3]=index;
      run(e,&s); uint8_t out[8]; assert(bb_read(e,s.x[1],out,sizeof(out)) && !memcmp(out,native,sizeof(out))); bb_destroy(e); }
    { /* MOV W zero-extends, including the zero register. */
      uint32_t p[]={0x2a0103e0,0x2a1f03e2,0xd65f03c0};
      uint64_t in=UINT64_C(0xabcdef0198765432),native;
      __asm__ volatile("mov %w0, %w1" : "=r"(native) : "r"(in));
      bb_engine *e=make(p,3,4); bb_state s=start(e,0); s.x[1]=in; s.x[2]=UINT64_MAX;
      run(e,&s); assert(s.x[0]==native && s.x[2]==0); bb_destroy(e); }
    { /* UBFM aliases: native LSL and extract, including W zero extension. */
      uint32_t p[]={0x531f7820,0x53053022,0xd65f03c0};
      uint64_t in=UINT64_C(0xffeeddcc87654321),left,extract;
      __asm__ volatile("lsl %w0, %w2, #1\n\tubfx %w1, %w2, #5, #8" : "=&r"(left),"=&r"(extract) : "r"(in));
      bb_engine *e=make(p,3,4); bb_state s=start(e,0); s.x[1]=in; run(e,&s);
      assert(s.x[0]==left && s.x[2]==extract); bb_destroy(e); }
    { /* Real virtual-dispatch address calculation: ADD with signed shift. */
      uint32_t p[]={0x8b890540,0xd65f03c0}; uint64_t a=UINT64_C(0x8000000000000000),b=UINT64_C(0xfffffffffffffff9),native;
      __asm__ volatile("add %0, %1, %2, asr #1" : "=r"(native) : "r"(a),"r"(b));
      bb_engine *e=make(p,2,4); bb_state s=start(e,0); s.x[10]=a; s.x[9]=b; s.nzcv=0xa0000000;
      run(e,&s); assert(s.x[0]==native && s.nzcv==0xa0000000); bb_destroy(e); }
    { /* SBFM ASR alias as used by libc++ pointer arithmetic. */
      uint32_t p[]={0x9343fc20,0xd65f03c0}; uint64_t src=UINT64_C(0x8000000000000001),native;
      __asm__ volatile("asr %0, %1, #3" : "=r"(native) : "r"(src));
      bb_engine *e=make(p,2,4); bb_state s=start(e,0); s.x[1]=src; run(e,&s);
      assert(s.x[0]==native); bb_destroy(e); }
    { /* The first SIMD operation encountered in libc++ initialization. */
      uint32_t p[]={0x6f00e400,0xd65f03c0}; uint64_t native[2]={1,2};
      __asm__ volatile("movi v0.2d, #0\n\tstr q0, [%0]" :: "r"(native) : "v0","memory");
      bb_engine *e=make(p,2,4); bb_state s=start(e,0); s.v[0][0]=7; s.v[0][1]=9;
      s.v[1][0]=11; s.v[1][1]=13; s.nzcv=0xa0000000; run(e,&s);
      assert(s.v[0][0]==native[0] && s.v[0][1]==native[1] && s.v[1][0]==11 && s.v[1][1]==13 && s.nzcv==0xa0000000);
      bb_destroy(e); }
    { /* Q-register stores encountered in real libc++ initialization. */
      uint32_t p[]={0x3c830c20,0xad020040,0x3d804040,0xd65f03c0};
      uint64_t vec[2]={UINT64_C(0x123456789abcdef0),UINT64_C(0xfedcba9876543210)};
      uint8_t native[320]={0},*cursor=native;
      __asm__ volatile("ldr q0, [%1]\n\tstr q0, [%0, #48]!" : "+r"(cursor) : "r"(vec) : "v0","memory");
      __asm__ volatile("ldr q0, [%1]\n\tstp q0, q0, [%0, #64]\n\tstr q0, [%0, #256]" :: "r"(native),"r"(vec) : "v0","memory");
      bb_engine *e=make(p,4,4); bb_state s=start(e,0); s.x[1]=s.x[2]=bb_base(e)+PAGE;
      memcpy(s.v[0],vec,16); run(e,&s); uint8_t actual[320]; assert(bb_read(e,bb_base(e)+PAGE,actual,sizeof(actual)));
      assert(!memcmp(actual,native,sizeof(actual)) && s.x[1]==bb_base(e)+PAGE+48 && cursor==native+48);
      bb_destroy(e); }
    { /* INS D[0] and unscaled Q store preserve the upper SIMD lane. */
      uint32_t p[]={0x4e081c20,0x3c818040,0xd65f03c0};
      uint64_t initial[2]={3,UINT64_C(0xfedcba9876543210)}, value=UINT64_C(0x1122334455667788); uint8_t native[64]={0};
      __asm__ volatile("ldr q0, [%1]\n\tins v0.d[0], %2\n\tstur q0, [%0, #24]" :: "r"(native),"r"(initial),"r"(value) : "v0","memory");
      bb_engine *e=make(p,3,4); bb_state s=start(e,0); s.x[1]=value; s.x[2]=bb_base(e)+PAGE;
      memcpy(s.v[0],initial,16); run(e,&s); uint64_t got[2]; assert(bb_read(e,s.x[2]+24,got,16));
      assert(!memcmp(got,native+24,16)); bb_destroy(e); }
    { /* The libc++ guard's TST immediate, compared with native NZCV. */
      uint32_t p[]={0x72001c3f,0xd65f03c0}; uint64_t inputs[]={0,0x80,0xff00,0x800000ff};
      bb_engine *e=make(p,2,4);
      for (unsigned i=0;i<4;i++) {
        uint64_t nzcv; __asm__ volatile("tst %w1, #0xff\n\tmrs %0, nzcv" : "=r"(nzcv) : "r"(inputs[i]) : "cc");
        bb_state s=start(e,0); s.x[1]=inputs[i]; run(e,&s); assert(s.nzcv==(nzcv&0xf0000000));
      }
      bb_destroy(e); }
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
    { /* One instruction, same initial state: native transfer vs checked interpreter. */
      uint32_t direct[]={0x14000000,0x15ffffff,0x16000000,0x17ffffff,
                         0x94000000,0x95ffffff,0x96000000,0x97ffffff};
      uint32_t p[]={0xd503201f}; bb_engine *e=make(p,1,4);
      for (unsigned i=0;i<8+3*31;++i) {
        uint32_t w=i<8?direct[i]:(uint32_t[]){0xd61f0000,0xd63f0000,0xd65f0000}[(i-8)/31] | (((i-8)%31)<<5);
        assert(bb_write(e,bb_base(e),&w,4)); bb_state a=start(e,0),b;
        for(unsigned j=0;j<31;++j) a.x[j]=UINT64_C(0x1234567800000001)+j*17;
        a.sp=bb_base(e)+PAGE*2; a.nzcv=0xb0000000; a.tpidr_el0=0x42; b=a;
        bb_stats before=bb_get_stats(e);
        bb_result x=bb_run(e,&a,END,1), y=bb_run_reference(e,&b,END,1);
        assert(x==y && !memcmp(&a,&b,sizeof(a)));
        bb_stats after=bb_get_stats(e);
        assert(after.native_instructions==before.native_instructions+1 && after.interpreted_instructions==before.interpreted_instructions+1);
      }
      /* Invalid and unaligned destinations are still rejected by the next fetch. */
      uint32_t br=0xd61f0060; assert(bb_write(e,bb_base(e),&br,4));
      for(unsigned i=0;i<2;++i) { bb_state a=start(e,0),b; a.x[3]=i?bb_base(e)+2:0x1000; b=a;
        bb_result x=bb_run(e,&a,END,2), y=bb_run_reference(e,&b,END,2);
        assert(x==y && x==(i?BB_ALIGNMENT:BB_MEMORY) && !memcmp(&a,&b,sizeof(a))); }
      bb_destroy(e); puts("native B/BL/BR/BLR/RET versus checked interpreter: 101 transfers and invalid targets passed"); }
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
      bb_stats stats=bb_get_stats(e); assert(stats.native_blocks==2 && stats.native_instructions==3 && stats.interpreted_instructions==0);
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
      puts("InitializeRequest::getRequestID: guest pointer and LR/PC preserved; native instructions=3, fallback=0; controlled invalidation and unsupported instruction passed");
      bb_destroy(e); free(image); }
    fclose(f); puts("block engine: native ADR/ADRP, cache, checked fallback, control flow, memory, invalidation and APK sequences passed");
}
