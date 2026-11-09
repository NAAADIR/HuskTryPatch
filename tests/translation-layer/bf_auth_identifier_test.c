/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "../../src/translation-layer-next/husk-tl-jni.c"

static char last_log[512];
void tl_log_line(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vsnprintf(last_log, sizeof(last_log), fmt, args);
    va_end(args);
}

int main(void)
{
    tl_jclass cls = { .name = "sg/gumi/bravefrontier/BraveFrontier" };
    tl_jmeth method = { .cls = &cls, .name = "getAndroidId", .sig = "()Ljava/lang/String;" };
    jobj id = { .kind = TL_K_STRING };
    id.str.utf8 = "123456789abcdef0";
    jvalue result = { .l = &id };
    bf_diag_identifier(&method, result);
    assert(strstr(last_log, "present=1 usable=1 consistent=unknown threw=0"));
    assert(!strstr(last_log, id.str.utf8));
    bf_diag_identifier(&method, result);
    assert(strstr(last_log, "consistent=yes"));
    id.str.utf8 = "123456789abcdef1";
    bf_diag_identifier(&method, result);
    assert(strstr(last_log, "consistent=no"));
    assert(!strstr(last_log, id.str.utf8));

    cls.name = "sg/gumi/bravefrontier/BraveFrontierJNI";
    method.name = "getDeviceAdvertisingID";
    id.str.utf8 = "00000000-0000-0000-0000-000000000000";
    bf_diag_identifier(&method, result);
    assert(strstr(last_log, "present=1 all_zero=1 threw=0"));
    assert(!strstr(last_log, id.str.utf8));
    id.str.utf8 = "----";
    bf_diag_identifier(&method, result);
    assert(strstr(last_log, "present=1 all_zero=0 threw=0"));
    t_pending = &id;
    bf_diag_identifier(&method, result);
    assert(strstr(last_log, "present=0 all_zero=0 threw=1"));
    t_pending = NULL;
    puts("BF identifier diagnostic redaction and consistency passed");
    return 0;
}
