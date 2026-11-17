/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Register-only FP/AdvSIMD instructions executed natively by the engine:
 * register renaming (high registers, H-size by-element index bit, wrapped TBL
 * table), NZCV in and out, general <-> SIMD operands with XZR, lane-preserving
 * forms. Every expected value is computed independently in C. */
#include "block_engine.h"
#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define PAGE 4096u
static const uint32_t code[]={
    0x4f03f611, /* fmov v17.4s, #1.0 */          0x9e620052, /* scvtf d18, x2 */
    0x1e3d2a93, /* fadd s19, s20, s29 */          0x1e752240, /* fcmp d18, d21 */
    0x1e78bef6, /* fcsel d22, d23, d24, lt */     0x1e780243, /* fcvtzs w3, d18 */
    0x0e0c3f25, /* umov w5, v25.s[1] */           0x4e040cda, /* dup v26.4s, w6 */
    0x4fbe139b, /* fmla v27.4s, v28.4s, v30.s[1] */ 0x4f7f8bf0, /* mul v16.8h, v31.8h, v15.h[7] */
    0x1f4c356a, /* fmadd d10, d11, d12, d13 */    0x4e181cee, /* mov v14.d[1], x7 */
    0x9eae01a8, /* fmov x8, v13.d[1] */           0x4e0923cc, /* tbl v12.16b, {v30.16b, v31.16b}, v9.16b */
    0x1e3d1682, /* fccmp s20, s29, #2, ne */      0x1e2303e8, /* ucvtf s8, wzr */
    0x4f02e747, /* movi v7.16b, #0x5a */          0x9e7803f3, /* fcvtzs x19, d31 */
    0x14000000, /* b . (stop target) */
};
static uint64_t f32(float f) { uint32_t u; memcpy(&u,&f,4); return u; }
static uint64_t f64(double d) { uint64_t u; memcpy(&u,&d,8); return u; }
static float as_f32(uint64_t v) { uint32_t u=(uint32_t)v; float f; memcpy(&f,&u,4); return f; }
static double as_f64(uint64_t v) { double d; memcpy(&d,&v,8); return d; }
/* Integer classes the interpreter lacks, mixed with an interpreted CMP. */
static const uint32_t icode[]={0x93407d16,0xb3783eb4,0xeb02003f,0xfa450864,0xba0600a4,0x1acd0987,0x9ad021ee,
    0x5ac01251,0xdac002f3,0x9bda7f38,0x13042f9b,0xfa4113e0,0x14000000};
static unsigned int_section(void) {
    uint8_t *image=calloc(1,PAGE); memcpy(image,icode,sizeof(icode));
    bb_engine *e=bb_create(image,PAGE,8); free(image); assert(e && bb_protect(e,0,PAGE,BB_R|BB_X));
    bb_state s={0}; uint64_t base=bb_base(e), end=base+(sizeof(icode)/4-1)*4; unsigned pass=0;
    s.pc=base; s.x[8]=0xfffffff0; s.x[20]=0x1111111111111111ull; s.x[21]=0xabcd; s.x[1]=5; s.x[2]=5; s.x[3]=7;
    s.x[5]=~0ull; s.x[6]=0; s.x[12]=100; s.x[13]=7; s.x[15]=3; s.x[16]=65; s.x[18]=0x10000; s.x[23]=1;
    s.x[25]=s.x[26]=0x100000000ull; s.x[28]=0xf80; s.x[22]=s.x[27]=0xdeadbeefdeadbeefull;
    assert(bb_run(e,&s,end,100)==BB_STOP && s.pc==end);
    assert(s.x[22]==(uint64_t)-16); ++pass;
    assert(s.x[20]==0x1111111111abcd11ull); ++pass;
    assert(s.x[4]==0); ++pass;                      /* ~0 + 0 + C(from ccmp) */
    assert(s.x[7]==14 && s.x[14]==6 && s.x[17]==15); ++pass;
    assert(s.x[19]==0x8000000000000000ull && s.x[24]==1); ++pass;
    assert(s.x[27]==0xfffffff8ull); ++pass;
    assert(s.nzcv==0); ++pass;                      /* ccmp xzr,x1,#0,ne with Z set -> #0 */
    bb_stats st=bb_get_stats(e); assert(st.interpreted_instructions==1); ++pass;   /* only the CMP */
    bb_destroy(e); return pass;
}
/* Interpreted sign-extending loads in every addressing form, and PRFM. */
static unsigned load_section(void) {
    static const uint32_t lcode[]={0x39c00c20,0x79800822,0xb89fc023,0x388014a4,0x78e77826,0xf9802020,0x14000000};
    uint8_t *image=calloc(1,PAGE*2); memcpy(image,lcode,sizeof(lcode));
    uint8_t data[16]={0x11,0x22,0x33,0x80,0xfe,0xff,0x7f,0x00,0x90,0x80,0x01,0x02,0x03,0x04,0x05,0x06};
    memcpy(image+PAGE+16,data,16); memcpy(image+PAGE+8,"\x00\x00\x00\x00\xfc\xff\xff\xff",8);
    bb_engine *e=bb_create(image,PAGE*2,8); free(image);
    assert(e && bb_protect(e,0,PAGE,BB_R|BB_X) && bb_protect(e,PAGE,PAGE,BB_R|BB_W));
    uint64_t base=bb_base(e), d=base+PAGE+16; bb_state s={0}; unsigned pass=0;
    s.pc=base; s.x[1]=d; s.x[5]=d+3; s.x[7]=4; s.x[0]=s.x[2]=s.x[3]=s.x[4]=s.x[6]=~0ull;
    assert(bb_run(e,&s,base+6*4,20)==BB_STOP);
    assert(s.x[0]==0xffffff80u); ++pass;                     /* ldrsb w0: byte 0x80 -> W sign, X upper clear */
    assert(s.x[2]==(uint64_t)(int64_t)(int16_t)0xfffe); ++pass; /* ldrsh x2 from bytes fe ff */
    assert(s.x[3]==(uint64_t)-4); ++pass;                    /* ldursw x3 at d-4 */
    assert(s.x[4]==(uint64_t)-128 && s.x[5]==d+4); ++pass;    /* post-index writeback */
    assert(s.x[6]==0xffff8090u); ++pass;                     /* ldrsh w6,[x1,x7,lsl#1]: d+8 holds 90 80 */
    bb_destroy(e); return pass;
}
/* Interpreted AdvSIMD LD1/ST1 single-lane, LD1R and multiple-register forms. */
static unsigned ld1_section(void) {
    static const uint32_t c[]={0x0d409143,0x4d40c944,0x4d9f4963,0x4c40a145,0x4c9f7d65,0x4dcc8547,0x14000000};
    uint8_t *image=calloc(1,PAGE*2); memcpy(image,c,sizeof(c));
    for (int i=0;i<32;i++) image[PAGE+i]=(uint8_t)i;
    bb_engine *e=bb_create(image,PAGE*2,8); free(image);
    assert(e && bb_protect(e,0,PAGE,BB_R|BB_X) && bb_protect(e,PAGE,PAGE,BB_R|BB_W));
    uint64_t base=bb_base(e), d=base+PAGE; bb_state s={0}; unsigned pass=0; uint8_t out[18];
    s.pc=base; s.x[10]=d; s.x[11]=d+64; s.x[12]=8; memset(s.v[3],0xaa,16); memset(s.v[7],0x55,16);
    assert(bb_run(e,&s,base+6*4,20)==BB_STOP);
    assert(s.v[3][0]==0x03020100aaaaaaaaull && s.v[3][1]==0xaaaaaaaaaaaaaaaaull); ++pass;   /* lane 1 only */
    assert(s.v[4][0]==0x0302010003020100ull && s.v[4][1]==s.v[4][0]); ++pass;               /* LD1R */
    assert(s.v[5][0]==0x0706050403020100ull && s.v[6][1]==0x1f1e1d1c1b1a1918ull); ++pass;   /* two registers */
    assert(bb_read(e,d+64,out,18) && out[0]==0xaa && out[1]==0xaa && out[2]==0 && out[17]==15 && s.x[11]==d+64+2+16); ++pass;
    assert(s.v[7][1]==0x0706050403020100ull && s.v[7][0]==0x5555555555555555ull && s.x[10]==d+8); ++pass;   /* register post-index */
    bb_destroy(e); return pass;
}
/* Interleaved ST2 (post-index), LD2 .8h and LD4 .16b. */
static unsigned ld24_section(void) {
    static const uint32_t c[]={0x4c9f88a2,0x4c4084a6,0x4c4000a8,0x14000000};
    uint8_t *image=calloc(1,PAGE*2); memcpy(image,c,sizeof(c));
    for (int k=0;k<64;k++) image[PAGE+32+k]=(uint8_t)(0x40+k);
    bb_engine *e=bb_create(image,PAGE*2,8); free(image);
    assert(e && bb_protect(e,0,PAGE,BB_R|BB_X) && bb_protect(e,PAGE,PAGE,BB_R|BB_W));
    uint64_t base=bb_base(e), d=base+PAGE; bb_state s={0}; unsigned pass=0; uint8_t m[32], v2[16], v3[16];
    for (int i=0;i<16;i++) { v2[i]=(uint8_t)i; v3[i]=(uint8_t)(0x10+i); }
    memcpy(s.v[2],v2,16); memcpy(s.v[3],v3,16); s.pc=base; s.x[5]=d;
    assert(bb_run(e,&s,base+3*4,10)==BB_STOP && s.x[5]==d+32);
    assert(bb_read(e,d,m,32));
    bool st=true; for (int i=0;i<4;i++) st=st && !memcmp(m+i*8,v2+i*4,4) && !memcmp(m+i*8+4,v3+i*4,4);
    assert(st); ++pass;                                                   /* words alternate v2, v3 */
    uint8_t v6[16], v7[16]; memcpy(v6,s.v[6],16); memcpy(v7,s.v[7],16);
    bool l2=true; for (int i=0;i<8;i++) l2=l2 && v6[2*i]==0x40+4*i && v7[2*i]==0x42+4*i;
    assert(l2); ++pass;                                                   /* even/odd halfwords */
    uint8_t v8[16], v11[16]; memcpy(v8,s.v[8],16); memcpy(v11,s.v[11],16);
    bool l4=true; for (int i=0;i<16;i++) l4=l4 && v8[i]==0x40+4*i && v11[i]==0x43+4*i;
    assert(l4); ++pass;                                                   /* every fourth byte */
    bb_destroy(e); return pass;
}
static unsigned st2_lane_section(void) {
    static const uint32_t c[]={0x0d209050,0x14000000};
    uint8_t *image=calloc(1,PAGE*2); memcpy(image,c,sizeof(c));
    bb_engine *e=bb_create(image,PAGE*2,8); free(image);
    assert(e && bb_protect(e,0,PAGE,BB_R|BB_X) && bb_protect(e,PAGE,PAGE,BB_R|BB_W));
    uint64_t base=bb_base(e), d=base+PAGE; bb_state s={0}; uint32_t m[2];
    s.v[16][0]=0x1111111122222222ull; s.v[17][0]=0x3333333344444444ull; s.pc=base; s.x[2]=d;
    assert(bb_run(e,&s,base+4,5)==BB_STOP && bb_read(e,d,m,8));
    unsigned pass=m[0]==0x11111111u && m[1]==0x33333333u;   /* lane 1 of v16, then of v17 */
    bb_destroy(e); return pass;
}
int main(void) {
    uint8_t *image=calloc(1,PAGE); memcpy(image,code,sizeof(code));
    bb_engine *e=bb_create(image,PAGE,8); free(image); assert(e && bb_protect(e,0,PAGE,BB_R|BB_W|BB_X));
    bb_state s={0}; uint64_t base=bb_base(e), end=base+(sizeof(code)/4-1)*4;
    s.pc=base; s.x[2]=(uint64_t)-3; s.x[6]=0x11223344; s.x[7]=0xfeedface12345678; s.x[19]=0x77;
    s.v[20][0]=f32(1.5f); s.v[29][0]=f32(2.25f); s.v[21][0]=f64(0.0);
    s.v[23][0]=f64(7.0); s.v[24][0]=f64(9.0);
    s.v[25][0]=0x00000002aaaaaaaaull; s.v[25][1]=0xffffffffffffffffull;
    s.v[27][0]=f32(1.0f)|(f32(2.0f)<<32); s.v[27][1]=f32(3.0f)|(f32(4.0f)<<32);
    s.v[28][0]=f32(10.0f)|(f32(20.0f)<<32); s.v[28][1]=f32(30.0f)|(f32(40.0f)<<32);
    s.v[30][0]=f32(99.0f)|(f32(0.5f)<<32); s.v[30][1]=0x0f0e0d0c0b0a0908ull;
    for (int i=0;i<4;i++) s.v[31][0]|=(uint64_t)(uint16_t)(i+1)<<(16*i), s.v[31][1]|=(uint64_t)(uint16_t)(i+5)<<(16*i);
    s.v[15][1]=(uint64_t)3<<48;   /* v15.h[7]=3 */
    s.v[11][0]=f64(2.0); s.v[12][0]=f64(3.0); s.v[13][0]=f64(4.0); s.v[13][1]=0xabcdef0011223344ull;
    s.v[14][0]=0x1111; s.v[9][0]=0x1f00110f1e0201ffull; s.v[9][1]=0x0706050403020100ull;
    s.v[31][1]=s.v[31][1]; s.v[8][1]=0xdead;
    bb_state before=s;
    bb_result r=bb_run(e,&s,end,1000); assert(r==BB_STOP && s.pc==end);
    bb_stats st=bb_get_stats(e);
    unsigned pass=0;
    assert(s.v[17][0]==(f32(1.0f)|f32(1.0f)<<32) && s.v[17][1]==s.v[17][0]); ++pass;
    assert(as_f64(s.v[18][0])==-3.0 && s.v[18][1]==0); ++pass;
    assert(as_f32(s.v[19][0])==3.75f && (s.v[19][0]>>32)==0 && s.v[19][1]==0); ++pass;
    /* fcmp -3.0, 0.0: N=1 (less than) -> lt holds; fcsel picks d23. Then fccmp
     * with ne true (Z=0) compares 1.5 vs 2.25 -> N=1, C=0, Z=0, V=0. */
    assert(as_f64(s.v[22][0])==7.0); ++pass;
    assert(s.x[3]==(uint32_t)-3); ++pass;
    assert(s.x[5]==2); ++pass;
    assert(s.v[26][0]==0x1122334411223344ull && s.v[26][1]==0x1122334411223344ull); ++pass;
    float lanes[4]={1+10*0.5f,2+20*0.5f,3+30*0.5f,4+40*0.5f};
    assert(as_f32(s.v[27][0])==lanes[0] && as_f32(s.v[27][0]>>32)==lanes[1] && as_f32(s.v[27][1])==lanes[2] && as_f32(s.v[27][1]>>32)==lanes[3]); ++pass;
    for (int i=0;i<8;i++) { uint16_t h=(uint16_t)(s.v[16][i/4]>>(16*(i%4))); assert(h==(uint16_t)(3*(i+1))); } ++pass;
    assert(as_f64(s.v[10][0])==4.0+2.0*3.0 && s.v[10][1]==0); ++pass;
    assert(s.v[14][0]==0x1111 && s.v[14][1]==0xfeedface12345678ull); ++pass;
    assert(s.x[8]==0xabcdef0011223344ull); ++pass;
    /* tbl: table bytes 0..15 = v30, 16..31 = v31; index >= 32 gives 0 */
    uint8_t table[32], idx[16], out[16]; memcpy(table,before.v[30],16); memcpy(table+16,before.v[31],16); memcpy(idx,before.v[9],16);
    for (int i=0;i<16;i++) out[i]=idx[i]<32?table[idx[i]]:0;
    assert(!memcmp(s.v[12],out,16)); ++pass;
    assert(s.nzcv==0x80000000u); ++pass;
    assert(s.v[8][0]==0 && s.v[8][1]==0); ++pass;
    assert(s.v[7][0]==0x5a5a5a5a5a5a5a5aull && s.v[7][1]==0x5a5a5a5a5a5a5a5aull); ++pass;
    assert(s.x[19]==(uint64_t)(int64_t)as_f64(before.v[31][0])); ++pass;
    /* Untouched registers are preserved, including the SP and other GPRs. */
    assert(s.sp==before.sp && s.x[2]==before.x[2] && s.x[6]==before.x[6] && s.v[20][0]==before.v[20][0] && s.v[29][0]==before.v[29][0]); ++pass;
    assert(st.native_instructions>=18 && st.interpreted_instructions==0);
    /* Budget of one: each FP/SIMD instruction is its own native block. */
    bb_state t=before; bb_result br; size_t steps=0;
    do { br=bb_run(e,&t,end,1); ++steps; } while (br==BB_BUDGET && steps<100);
    assert(br==BB_STOP && !memcmp(t.v,s.v,sizeof(s.v)) && !memcmp(t.x,s.x,sizeof(s.x)) && t.nzcv==s.nzcv); ++pass;
    /* Unaccepted forms stay unsupported: FP16 FADD, MRS FPCR. */
    uint32_t bad[]={0x1ee22820 /* fadd h0,h1,h2 */, 0xd53b4400 /* mrs x0, fpcr */};
    for (size_t i=0;i<2;i++) { assert(bb_write(e,base,&bad[i],4)); bb_state u={0}; u.pc=base; assert(bb_run(e,&u,end,10)==BB_UNSUPPORTED); }
    ++pass;
    unsigned ipass=int_section(), lpass=load_section(), vpass=ld1_section(), ipass2=ld24_section()+st2_lane_section();
    printf("simd native: %u/20 PASS (native=%zu interpreted=%zu); integer native: %u/8 PASS; sign-extending loads: %u/5 PASS; ld1/st1: %u/5 PASS; ld2-4/st2-4: %u/4 PASS\n",pass,st.native_instructions,st.interpreted_instructions,ipass,lpass,vpass,ipass2);
    bb_destroy(e); return pass==20 && ipass==8 && lpass==5 && vpass==5 && ipass2==4?0:1;
}
