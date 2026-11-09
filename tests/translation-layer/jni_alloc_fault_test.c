/* Inject object and backing allocation failures at JNI entry points. */
#include <stdlib.h>
static void *fault_calloc(size_t n, size_t size);
static void fault_free(void *p);
#define calloc fault_calloc
#define free fault_free
#include "husk-tl-jni.c"
#undef calloc
#undef free
#include <assert.h>
void tl_log_line(const char *fmt, ...) { (void)fmt; }
static int calls, fail_at, frees;
static void fault_free(void *p) { if (p) frees++; free(p); }
static void *fault_calloc(size_t n, size_t size) {
    if (++calls == fail_at || fail_at < 0) return NULL;
    return calloc(n, size);
}
int main(void) {
    static tl_jclass cls, objcls, oomcls, stringcls, negcls;
    static jobj pending;
    cls.name = "[B";
    cls.next = g_classes[hash_str(cls.name) % NBUCKETS]; g_classes[hash_str(cls.name) % NBUCKETS] = &cls;
    objcls.name = "[Ljava/lang/Object;";
    objcls.next = g_classes[hash_str(objcls.name) % NBUCKETS]; g_classes[hash_str(objcls.name) % NBUCKETS] = &objcls;
    oomcls.name = "java/lang/OutOfMemoryError";
    oomcls.next = g_classes[hash_str(oomcls.name) % NBUCKETS]; g_classes[hash_str(oomcls.name) % NBUCKETS] = &oomcls;
    negcls.name = "java/lang/NegativeArraySizeException";
    negcls.next = g_classes[hash_str(negcls.name) % NBUCKETS]; g_classes[hash_str(negcls.name) % NBUCKETS] = &negcls;
    stringcls.name = "java/lang/String";
    stringcls.next = g_classes[hash_str(stringcls.name) % NBUCKETS]; g_classes[hash_str(stringcls.name) % NBUCKETS] = &stringcls;
    fail_at = 1;
    assert(!tl_jni_new_prim_array('B', 4));
    assert(t_pending && t_pending->cls == &oomcls); t_pending = NULL;
    calls = 0; fail_at = 2;
    jobj *a = tl_jni_new_prim_array('B', 4);
    assert(!a && t_pending && t_pending->cls == &oomcls); t_pending = NULL;
    calls = 0; frees = 0; fail_at = 2;
    assert(!tl_jni_try_new_prim_array('B', 4) && !t_pending && frees == 1);
    /* Keep a pending exception to verify it survives without requiring an
     * exception allocation during fault injection. */
    t_pending = &pending;
    calls = 0; fail_at = -1; assert(!tl_jni_new_prim_array('B', 4) && t_pending == &pending);
    assert(!jni_NewByteArray(NULL, -1) && t_pending == &pending);
    assert(!jni_NewObjectArray(NULL, -1, NULL, NULL) && t_pending == &pending);
    calls = 0; fail_at = 1; assert(!tl_jni_new_prim_array('B', 4) && t_pending == &pending);
    calls = 0; frees = 0; fail_at = 2; assert(!tl_jni_new_prim_array('B', 4) && t_pending == &pending && frees == 1);
    calls = 0; fail_at = 1; assert(!jni_NewByteArray(NULL, 4) && t_pending == &pending);
    calls = 0; fail_at = 2; assert(!jni_NewByteArray(NULL, 4) && t_pending == &pending);
    calls = 0; fail_at = 1; assert(!jni_NewObjectArray(NULL, 4, NULL, NULL) && t_pending == &pending);
    calls = 0; fail_at = 2; assert(!jni_NewObjectArray(NULL, 4, NULL, NULL) && t_pending == &pending);
    t_pending = NULL; calls = 0; fail_at = 2;
    assert(!jni_NewByteArray(NULL, 4) && t_pending && t_pending->cls == &oomcls);
    t_pending = NULL; calls = 0; fail_at = 0;
    assert(!jni_NewByteArray(NULL, -1) && t_pending && t_pending->cls == &negcls);
    t_pending = NULL;
    a = jni_NewByteArray(NULL, 0); assert(a && a->arr.data && !a->arr.len); tl_jni_unref(a);
    a = jni_NewObjectArray(NULL, 0, NULL, NULL); assert(a && a->oarr.v && !a->oarr.len); tl_jni_unref(a);
    return 0;
}
