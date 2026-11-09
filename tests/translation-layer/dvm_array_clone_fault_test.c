#include "husk-tl-dvm-natives.c"
#include <assert.h>
static int failure, pending, threw, primitive_calls, fail_primitive_at;
bool tl_jni_pending(void) { return pending != 0; }
void tl_jni_throw(const char *cls, const char *msg) { (void)cls; (void)msg; pending = 1; }
tl_jclass *tl_jni_class(const char *name) { (void)name; static tl_jclass c; return &c; }
bool dvm_throw(const char *cls, const char *fmt, ...) { (void)fmt; assert(!strcmp(cls, "java/lang/OutOfMemoryError")); threw++; return false; }
jobj *tl_jni_new_prim_array(char type, uint32_t len) {
    if (fail_primitive_at && ++primitive_calls == fail_primitive_at) { pending = 1; return NULL; }
    if (failure == 1) return NULL;
    jobj *o = calloc(1, sizeof(*o)); o->kind = TL_K_PRIM_ARRAY; o->arr.etype = type; o->arr.len = len; o->arr.esz = 1;
    if (!failure) o->arr.data = calloc(len ? len : 1, 1);
    return o;
}
jobj *tl_jni_new_obj_array(tl_jclass *cls, uint32_t len) {
    (void)cls; if (failure == 1) return NULL;
    jobj *o = calloc(1, sizeof(*o)); o->kind = TL_K_OBJ_ARRAY; o->oarr.len = len;
    if (!failure) o->oarr.v = calloc(len ? len : 1, sizeof(jobj *));
    return o;
}
int main(void) {
    uint8_t bytes[] = {1, 2}; jobj *elements[] = {NULL}; jvalue ret = {0};
    jobj src = {0}; src.kind = TL_K_PRIM_ARRAY; src.arr.etype = 'B'; src.arr.esz = 1; src.arr.len = 2; src.arr.data = bytes;
    for (failure = 1; failure <= 2; failure++) { threw = 0; assert(!Object_internalClone(&src, NULL, &ret) && threw == 1); }
    pending = 1; threw = 0; assert(!Object_internalClone(&src, NULL, &ret) && threw == 0); pending = 0;
    failure = 0; assert(Object_internalClone(&src, NULL, &ret)); jobj *clone = ret.l;
    assert(!memcmp(clone->arr.data, bytes, 2)); free(clone->arr.data); free(clone);
    memset(&src, 0, sizeof(src)); src.kind = TL_K_OBJ_ARRAY; src.oarr.len = 1; src.oarr.v = elements;
    for (failure = 1; failure <= 2; failure++) { threw = 0; assert(!Object_internalClone(&src, NULL, &ret) && threw == 1); }
    failure = 0; src.oarr.len = 0; assert(Object_internalClone(&src, NULL, &ret)); clone = ret.l; free(clone->oarr.v); free(clone);
    int32_t dims[] = {3, 2}; primitive_calls = 0; fail_primitive_at = 2;
    assert(!multi_array("B", dims, 2) && pending && primitive_calls == 2);
    return 0;
}
