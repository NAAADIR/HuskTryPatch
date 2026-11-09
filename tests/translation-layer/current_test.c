#include <assert.h>
#include "husk-tl-current.h"
static int calls;
static unsigned mock(void *d, void *draw, void *read, void *ctx) {
    assert(d == (void *)1 && draw == (void *)2 && read == draw && ctx == (void *)3);
    calls++; return calls == 1;
}
int main(void) {
    atomic_bool ended = false;
    assert(tl_checked_current(mock, (void *)1, (void *)2, (void *)3, &ended));
    assert(!atomic_load(&ended) && calls == 1);
    assert(!tl_checked_current(mock, (void *)1, (void *)2, (void *)3, &ended));
    assert(atomic_load(&ended) && calls == 2);
    return 0;
}
