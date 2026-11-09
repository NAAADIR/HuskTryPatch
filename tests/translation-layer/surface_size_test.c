#include <assert.h>
#include <pthread.h>
#include "husk-tl-surface-size.h"

static tl_surface_size size;
static void *writer(void *unused) {
    (void)unused;
    for (int i = 0; i < 500000; ++i) tl_surface_update(&size, (i & 1) ? 1170 : 2532, (i & 1) ? 2532 : 1170);
    return 0;
}
int main(void) {
    atomic_init(&size, tl_surface_pack(1170, 2532));
    assert(!tl_surface_update(&size, 0, 5));
    pthread_t t; assert(!pthread_create(&t, 0, writer, 0));
    for (int i = 0; i < 500000; ++i) {
        int w, h; tl_surface_load(&size, &w, &h);
        assert((w == 1170 && h == 2532) || (w == 2532 && h == 1170));
    }
    assert(!pthread_join(t, 0));
    return 0;
}
