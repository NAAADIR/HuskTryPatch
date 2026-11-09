/* Execute the framework's compiled ResizeMailbox methods in the DVM. */
#include "husk-tl-dvm.c"
#include <assert.h>

void tl_log_line(const char *fmt, ...) { (void)fmt; }
static dvm_method put, take;
static jobj box;

static void call_put(int w, int h) {
    uint64_t regs[32] = {0}; jvalue r;
    assert(put.regs <= 32);
    int i = put.regs - put.ins;
    regs[i] = (uintptr_t)&box; regs[i + 1] = (uint32_t)w; regs[i + 2] = (uint32_t)h;
    assert(interpret(&put, regs, &r));
}
static int64_t call_take(void) {
    uint64_t regs[32] = {0}; jvalue r;
    assert(take.regs <= 32);
    regs[take.regs - take.ins] = (uintptr_t)&box;
    assert(interpret(&take, regs, &r)); return r.j;
}
static void *worker(void *p) {
    int id = (int)(intptr_t)p;
    for (int i = 1; i <= 10000; i++) {
        call_put(id, id * 10000 + i);
        int64_t v = call_take();
        if (v) { int w = (int)(v >> 32), h = (int)v; assert((w == 1 || w == 2) && h > w * 10000 && h <= (w + 1) * 10000); }
    }
    return NULL;
}
int main(int argc, char **argv) {
    assert(argc == 2);
    FILE *f = fopen(argv[1], "rb"); assert(f);
    fseek(f, 0, SEEK_END); long n = ftell(f); rewind(f);
    uint8_t *bytes = malloc((size_t)n); assert(bytes && fread(bytes, 1, (size_t)n, f) == (size_t)n); fclose(f);
    assert(dex_add(bytes, (size_t)n, argv[1]));
    cdef *def = cdef_find("android/opengl/ResizeMailbox"); assert(def);
    dvm_dex *dex = def->dex;
    const uint8_t *cd = dex->b + dex->cls_off + def->def * 32;
    const uint8_t *p = dex->b + rd32(cd + 24);
    unsigned nsf = uleb(&p), nif = uleb(&p), ndm = uleb(&p), nvm = uleb(&p);
    assert(nsf == 0 && nif == 1);
    unsigned field_idx = uleb(&p); (void)uleb(&p);
    static tl_jclass jc; static dvm_class cls; static dvm_field field;
    static fref ref; static jvalue value;
    cls.dex = dex; cls.jc = &jc; cls.nslots = 1; cls.name = jc.name = "android/opengl/ResizeMailbox";
    jc.dvm = &cls; field.cls = &cls; field.name = "pending"; field.type = "J"; field.slot = 0;
    ref.df = &field; ref.type = 'J'; dex->fcache[field_idx] = (dvm_field *)&ref;
    box.kind = TL_K_OBJECT; box.cls = &jc; box.fields = &value; box.nfields = 1;
    for (int group = 0; group < 2; group++) {
        unsigned idx = 0, count = group ? nvm : ndm;
        for (unsigned i = 0; i < count; i++) {
            idx += uleb(&p); unsigned flags = uleb(&p), off = uleb(&p);
            const char *name = dex_str(dex, rd32(dex->b + dex->meth_off + idx * 8 + 4));
            dvm_method *m = !strcmp(name, "put") ? &put : !strcmp(name, "take") ? &take : NULL;
            if (m) {
                const uint8_t *code = dex->b + off;
                m->cls = &cls; m->flags = flags; m->regs = rd16(code); m->ins = rd16(code + 2);
                m->ntries = rd16(code + 6); m->ninsns = rd32(code + 12); m->insns = (const uint16_t *)(code + 16);
            }
        }
    }
    assert(put.insns && take.insns);
    call_put(320, 568); assert(call_take() == ((int64_t)320 << 32 | 568)); assert(!call_take());
    call_put(0, 568); assert(!call_take());
    pthread_t a, b; assert(!pthread_create(&a, NULL, worker, (void *)1)); assert(!pthread_create(&b, NULL, worker, (void *)2));
    assert(!pthread_join(a, NULL) && !pthread_join(b, NULL));
    return 0;
}
