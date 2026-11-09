/* Exercise the DVM's real array construction with injected allocation failures. */
#include "husk-tl-dvm.c"
#include <assert.h>

static int failure;
jobj *tl_jni_new_prim_array(char type, uint32_t len) {
    if (failure == 1) return NULL;
    jobj *a = calloc(1, sizeof(*a));
    a->kind = TL_K_PRIM_ARRAY; a->arr.etype = type; a->arr.len = len;
    if (!failure) a->arr.data = calloc(len ? len : 1, 1);
    return a;
}
jobj *tl_jni_new_obj_array(tl_jclass *elem, uint32_t len) {
    (void)elem;
    if (failure == 1) return NULL;
    jobj *a = calloc(1, sizeof(*a));
    a->kind = TL_K_OBJ_ARRAY; a->oarr.len = len;
    if (!failure) a->oarr.v = calloc(len ? len : 1, sizeof(jobj *));
    return a;
}

int main(void) {
    tl_jclass cls = {0}; cls.name = "[B";
    failure = 1; assert(!new_array(&cls, 4));
    failure = 2; assert(!new_array(&cls, 4));
    failure = 0; jobj *a = new_array(&cls, 4);
    assert(a && a->arr.data && a->arr.len == 4);
    free(a->arr.data); free(a);
    return 0;
}
