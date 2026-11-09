#include "husk-tl-dvm-natives.c"
#include <assert.h>
static const char *thrown;
bool dvm_throw(const char *cls, const char *fmt, ...) { (void)fmt; thrown = cls; return false; }
int main(void) {
    jobj src = {0}, dst = {0}; jvalue a[5] = {{0}}, ret = {0};
    src.kind = dst.kind = TL_K_PRIM_ARRAY;
    src.arr.etype = dst.arr.etype = 'B'; src.arr.esz = dst.arr.esz = 1;
    a[0].l = &src; a[2].l = &dst;
    assert(System_arraycopy(NULL, a, &ret));
    a[1].i = -1; assert(!System_arraycopy(NULL, a, &ret));
    assert(thrown && !strcmp(thrown, "java/lang/ArrayIndexOutOfBoundsException"));
    unsigned char buf[] = {1, 2, 3, 4}; src.arr.data = dst.arr.data = buf; src.arr.len = dst.arr.len = 4;
    a[1].i = 0; a[4].i = 1; src.arr.data = NULL; thrown = NULL;
    assert(!System_arraycopy(NULL, a, &ret));
    assert(thrown && !strcmp(thrown, "java/lang/OutOfMemoryError"));
    assert(buf[0] == 1);
    src.arr.data = buf; dst.arr.data = NULL; thrown = NULL;
    assert(!System_arraycopy(NULL, a, &ret));
    assert(thrown && !strcmp(thrown, "java/lang/OutOfMemoryError"));
    dst.arr.data = buf;
    a[1].i = 0; a[3].i = 1; a[4].i = 3;
    assert(System_arraycopy(NULL, a, &ret));
    assert(buf[0] == 1 && buf[1] == 1 && buf[2] == 2 && buf[3] == 3);
    return 0;
}
