/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "../../src/translation-layer-next/husk-tl-bionic.c"

static char log_line[256];
void tl_log_line(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(log_line, sizeof(log_line), fmt, ap);
    va_end(ap);
    errno = EIO;
    *tl_guest_errno_ptr() = 5;
}

static uint32_t fake_body = 0x1432b0ad;
tl_lib *tl_ld_find_lib(const char *name) { return !strcmp(name, "libgame.so") || !strcmp(name, "libgcore.so") ? (tl_lib *)1 : NULL; }
void *tl_ld_lib_base(const tl_lib *lib) { (void)lib; return (void *)((uintptr_t)&fake_body - 0x13a50dc); }
void *tl_ld_sym_deep(tl_lib *lib, const char *name, tl_lib **found)
{ (void)lib; (void)name; (void)found; return &fake_body; }

int main(void)
{
    atomic_store(&bf_gcore_diag_enabled, true);
    errno = EINVAL;
    *tl_guest_errno_ptr() = 22;
    tl_bf_gcore_diag_syscall(270, 8);
    assert(strstr(log_line, "self_read=positive errno=0 caller=unknown"));
    assert(errno == EINVAL && *tl_guest_errno_ptr() == 22);
    log_line[0] = 0;
    tl_bf_gcore_diag_syscall(63, -1);
    assert(!log_line[0]);
    tl_bf_gcore_diag_syscall(270, -14);
    assert(strstr(log_line, "self_read=error errno=14 caller=unknown"));
    assert(errno == EINVAL && *tl_guest_errno_ptr() == 22);
    puts("BF Initialize diagnostic reports only syscall outcome and preserves errno");
    return 0;
}
