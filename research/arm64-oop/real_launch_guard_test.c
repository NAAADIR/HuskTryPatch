/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "husk-jit-arena.h"
#include "husk-tl-unity-app.h"
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
int tl_log_sink_fd=-1;
void tl_log_line(const char *fmt, ...) {
    va_list ap; va_start(ap,fmt); vfprintf(stderr,fmt,ap); fputc('\n',stderr); va_end(ap);
}
int main(void) {
    assert(husk_oop_claim_xmem());
    assert(!husk_unity_launch("dummy.apk","dummy",(void *)1,1,1,"dummy",NULL));
    assert(husk_native_loaded_apk()==NULL);
    puts("native game launch refused after diagnostic allocator claim: PASS");
}
