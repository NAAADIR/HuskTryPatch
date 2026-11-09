#include "husk-tl-dvm-android.c"
#include <assert.h>
#include <stdarg.h>
static int calls, fail_at, taken, released, callbacks, draws, swaps, no_frame, verify_order;
static int unavailable_queries;
static long long pending_resize;
void tl_log_line(const char *fmt, ...) { (void)fmt; }
void *tl_nwindow_get(void) { return (void *)1; }
bool tl_ui_frame_take(const uint8_t **p, int *w, int *h, bool *any) { if (no_frame) return false; *p=NULL; *w=*h=1; *any=false; taken++; return true; }
void tl_ui_frame_done(void) { released++; }
tl_jclass *dvm_class_named(const char *name) { (void)name; return (tl_jclass *)1; }
jobj *dvm_new_object(tl_jclass *cls) { (void)cls; static jobj object; return &object; }
jvalue *dvm_slots(jobj *o) { (void)o; static jvalue slot; return &slot; }
bool tl_jni_pending(void) { return false; }
jvalue tl_jni_call(jobj *o, const char *name, const char *sig, const jvalue *args) {
    (void)o; (void)sig; (void)args; callbacks++;
    if (verify_order) {
        static const char *expected[] = { "huskHasSurface", "onSurfaceCreated", "huskHasSurface", "huskBeginFrame", "huskTakeResize", "onSurfaceChanged", "onDrawFrame" };
        assert(callbacks <= 7 && !strcmp(name, expected[callbacks - 1]));
    }
    if (!strcmp(name, "onDrawFrame")) draws++;
    jvalue r = {0};
    if (!strcmp(name, "huskHasSurface")) { r.z = unavailable_queries == 0; if (unavailable_queries) unavailable_queries--; }
    if (!strcmp(name, "huskTakeResize")) { r.j = pending_resize; pending_resize = 0; }
    if (!strcmp(name, "onSurfaceChanged")) assert(args[1].i == 20 && args[2].i == 30);
    return r;
}
static void *display(void *p) { (void)p; return (void *)1; }
static unsigned init(void *d,int *a,int *b) { (void)d; *a=1; *b=4; return 1; }
static unsigned api(unsigned x) { (void)x; return 1; }
static unsigned choose(void *d,const int *a,void **c,int n,int *out) { (void)d;(void)a;(void)n; *c=(void *)1;*out=1; return 1; }
static void *context(void *d,void *c,void *s,const int *a) { (void)d;(void)c;(void)s;(void)a;return (void *)2; }
static void *surface(void *d,void *c,void *w,const int *a) { (void)d;(void)c;(void)w;(void)a;return (void *)3; }
static unsigned current(void *d,void *a,void *b,void *c) { (void)d;(void)a;(void)b;(void)c; return ++calls != fail_at; }
static unsigned swap(void *d,void *s) { (void)d;(void)s; assert(calls < fail_at && "swap after failure"); swaps++; return 1; }
static unsigned interval(void *d,int x) { (void)d;(void)x;return 1; }
static unsigned query(void *d,void *s,int k,int *v) { (void)d;(void)s;(void)k;*v=10;return 1; }
static unsigned make(void) {return 1;}
static unsigned shader(unsigned a) {(void)a;return 1;}
static void source(unsigned a,int b,const char *const*c,const int*d) {(void)a;(void)b;(void)c;(void)d;}
static void one(unsigned a) {(void)a;}
static void two(unsigned a,unsigned b) {(void)a;(void)b;}
static void attrib(unsigned a,unsigned b,const char*c) {(void)a;(void)b;(void)c;}
static void gen(int n,unsigned *p) {for(int i=0;i<n;i++)p[i]=1;}
static void data(unsigned a,intptr_t b,const void*c,unsigned d) {(void)a;(void)b;(void)c;(void)d;}
void *tl_egl_resolve(const char *n) {
#define R(name,fn) if(!strcmp(n,name)) return (void *)fn
 R("eglGetDisplay",display);R("eglInitialize",init);R("eglBindAPI",api);R("eglChooseConfig",choose);R("eglCreateContext",context);R("eglCreateWindowSurface",surface);R("eglMakeCurrent",current);R("eglSwapBuffers",swap);R("eglSwapInterval",interval);R("eglQuerySurface",query);R("glCreateShader",shader);R("glShaderSource",source);R("glCompileShader",one);R("glCreateProgram",make);R("glAttachShader",two);R("glBindAttribLocation",attrib);R("glLinkProgram",one);R("glGenTextures",gen);R("glGenBuffers",gen);R("glBindBuffer",two);R("glBufferData",data);
 return NULL;
}
int main(void) {
 atomic_store(&g_screen_size,tl_surface_pack(10,10));
 atomic_store(&A.ended,false); calls=0; fail_at=1; A.gl_renderer=NULL;
 gl_main(NULL); assert(atomic_load(&A.ended) && calls==1 && taken==0 && released==0);
 atomic_store(&A.ended,false); calls=0; fail_at=2; A.gl_renderer=(jobj *)1;
 gl_main(NULL); assert(atomic_load(&A.ended) && calls==2 && taken==0 && released==0);
 atomic_store(&A.ended,false); calls=0; fail_at=2; A.gl_renderer=NULL; taken=released=0;
 gl_main(NULL); assert(atomic_load(&A.ended) && calls==2 && taken==1 && released==1);
 atomic_store(&A.ended,false); calls=0; fail_at=3; taken=released=0;
 gl_main(NULL); assert(atomic_load(&A.ended) && calls==3 && taken==1 && released==1);
 atomic_store(&A.ended,false); calls=0; fail_at=4; taken=released=callbacks=draws=0; A.gl_renderer=(jobj *)1;
 gl_main(NULL); assert(atomic_load(&A.ended) && calls==4 && taken==1 && released==1 && callbacks==2 && draws==0);
 atomic_store(&A.ended,false); calls=0; fail_at=5; taken=released=callbacks=draws=swaps=0;
 pending_resize = ((long long)20 << 32) | 30; verify_order=1;
 gl_main(NULL); assert(atomic_load(&A.ended) && calls==5 && callbacks==7 && draws==1 && swaps==0);
 atomic_store(&A.ended,false); calls=0; fail_at=4; taken=released=callbacks=draws=swaps=0; no_frame=1; pending_resize=0; verify_order=0;
 gl_main(NULL); assert(atomic_load(&A.ended) && calls==4 && callbacks==5 && draws==0 && swaps==0 && taken==released);
 atomic_store(&A.ended,false); calls=0; fail_at=2; callbacks=draws=0; unavailable_queries=1;
 gl_main(NULL); assert(atomic_load(&A.ended) && calls==2 && callbacks==2 && draws==0);
 return 0;
}
