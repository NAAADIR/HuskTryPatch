#include "husk-tl-dvm-android.c"
#include <assert.h>
static int oom;
bool tl_jni_pending(void) { return false; }
jobj *tl_jni_new_prim_array(char type, uint32_t len) { (void)type; (void)len; return NULL; }
jobj *tl_jni_try_new_prim_array(char type, uint32_t len) { (void)type; (void)len; return NULL; }
jobj *tl_jni_new_obj_array(tl_jclass *cls, uint32_t len) { (void)cls; (void)len; jobj *a = calloc(1, sizeof(*a)); a->kind = TL_K_OBJ_ARRAY; return a; }
tl_jclass *tl_jni_class(const char *name) { (void)name; return NULL; }
bool dvm_throw(const char *cls, const char *fmt, ...) { (void)fmt; oom = !strcmp(cls, "java/lang/OutOfMemoryError"); return false; }

static void *resize_worker(void *p) {
    int id = (int)(intptr_t)p;
    for (int i = 1; i <= 10000; i++) tl_javaapp_resize(id * 100000 + i, id * 100000 + i + 1);
    return NULL;
}

int main(void) {
    atomic_store(&g_screen_size, tl_surface_pack(1, 2));
    for (int i = 0; i < 1024; i++) tl_javaapp_touch(1, i, 0, 0);
    assert(A.qn == 4096);
    tl_javaapp_resize(320, 568);
    assert(A.qn == 4100 && A.q[4096] == 10);
    tl_javaapp_touch(4, 42, 0, 0);
    assert(A.qn == 4100);
    pthread_t a, b;
    assert(!pthread_create(&a, NULL, resize_worker, (void *)1));
    assert(!pthread_create(&b, NULL, resize_worker, (void *)2));
    assert(!pthread_join(a, NULL) && !pthread_join(b, NULL));
    int w, h; tl_surface_load(&g_screen_size, &w, &h);
    assert(h == w + 1 && E2.w == w && E2.h == h);
    assert(A.qn == 4100 && A.q[4096] == 10);
    for (int i = 0; i < 1024; i++) assert(A.q[4*i] == 1 && A.q[4*i+1] == i);
    jvalue ret = {0};
    assert(!N_pollInput(NULL, NULL, &ret) && oom && A.qn == 4100 && A.q[4096] == 10);
    assert(!pthread_mutex_trylock(&A.q_lock)); pthread_mutex_unlock(&A.q_lock);
    oom = 0; A.ntext = 1;
    assert(!N_pollText(NULL, NULL, &ret) && oom && A.ntext == 1);
    assert(!pthread_mutex_trylock(&A.t_lock)); pthread_mutex_unlock(&A.t_lock);
    oom = 0; assert(!N_insets(NULL, NULL, &ret) && oom);
    return 0;
}
