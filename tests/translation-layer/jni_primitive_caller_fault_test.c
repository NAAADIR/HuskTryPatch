#include "husk-tl-jni-security.c"
#include <assert.h>
static int pending;
jobj *tl_jni_new_prim_array(char type, uint32_t len) { (void)type; (void)len; pending = 1; return NULL; }
bool tl_jni_pending(void) { return pending != 0; }
void tl_jni_throw(const char *cls, const char *msg) { (void)cls; (void)msg; pending = 1; }
int main(void) {
    uint8_t data[] = {1, 2};
    assert(!bytes_array(data, sizeof(data)) && pending);
    jobj input = {0}; input.kind = TL_K_PRIM_ARRAY; input.arr.data = data; input.arr.len = 2; input.arr.esz = 1; input.arr.etype = 'B';
    jvalue args[3] = {{0}}; args[0].l = &input; args[1].i = 0; args[2].i = 2;
    tl_jcall call = {0}; call.args = args;
    pending = 0; Arrays_copyOfRange(&call); assert(pending && !call.ret.l);
    pending = 0; args[1].i = 2; Arrays_copyOf(&call); assert(pending && !call.ret.l);
    return 0;
}
