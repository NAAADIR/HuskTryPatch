/* Exercise the actual DVM monitor implementation, including first-use races. */
#include "husk-tl-dvm.c"
#include <assert.h>

static jobj object;
static int counter;
static void *worker(void *unused) {
    (void)unused;
    for (int i = 0; i < 20000; ++i) {
        dvm_monitor_enter(&object);
        assert(dvm_holds_lock(&object));
        ++counter;
        assert(dvm_monitor_exit(&object));
    }
    return NULL;
}
int main(void) {
    pthread_t threads[8];
    for (int i = 0; i < 8; ++i) assert(!pthread_create(&threads[i], NULL, worker, NULL));
    for (int i = 0; i < 8; ++i) assert(!pthread_join(threads[i], NULL));
    assert(counter == 160000);
    assert(!dvm_holds_lock(&object));
    dvm_monitor_enter(&object);
    dvm_monitor_enter(&object);
    assert(dvm_monitor_exit(&object) && dvm_holds_lock(&object));
    assert(dvm_monitor_exit(&object) && !dvm_holds_lock(&object));
    /* Run the DEX instructions emitted for synchronized blocks as well. */
    const uint16_t code[] = { 0x001d, 0x001e, 0x000e };
    dvm_dex dex = {0}; dvm_class cls = { .dex = &dex };
    dvm_method method = { .cls = &cls, .insns = code, .ninsns = 3 };
    uint64_t regs[] = { (uintptr_t)&object }; jvalue ret;
    assert(interpret(&method, regs, &ret));
    assert(!dvm_holds_lock(&object));
    return 0;
}
