/* SPDX-License-Identifier: GPL-2.0-or-later */
#define HUSK_BF_INIT_AUDIT 1
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "../../src/translation-layer-next/husk-tl-jni.c"

static char captured[256];
static int guest_errno;
int *tl_guest_errno_ptr(void) { return &guest_errno; }
void tl_log_line(const char *fmt, ...) {
    va_list ap; va_start(ap,fmt); vsnprintf(captured,sizeof(captured),fmt,ap); va_end(ap);
    errno=EIO; guest_errno=5;
}
int main(void) {
    tl_jclass cls={.name="sg/gumi/bravefrontier/BraveFrontierJNI"};
    tl_jmeth m={.cls=&cls,.name="getDeviceAdvertisingID",.sig="()Ljava/lang/String;"};
    jobj id={.kind=TL_K_STRING}; id.str.utf8="private-identifier";
    jvalue value={.l=&id}; errno=EINVAL; guest_errno=22;
    bf_init_provider_shape(&m,value);
    assert(strstr(captured,"provider=advertising_id scope=unattributed kind=string length=18 truncated=0"));
    assert(!strstr(captured,id.str.utf8) && errno==EINVAL && guest_errno==22);
    m.name="getISOCountryCode"; id.str.utf8=""; bf_init_provider_shape(&m,value);
    assert(strstr(captured,"provider=sim_country scope=unattributed kind=string length=0"));
    m.name="getDeviceModel"; value.l=NULL; bf_init_provider_shape(&m,value);
    assert(strstr(captured,"provider=device_model scope=unattributed kind=null length=-1"));
    t_pending=&id; bf_init_provider_shape(&m,value);
    assert(strstr(captured,"kind=exception length=-1") && t_pending==&id); t_pending=NULL;
    char long_value[131]; memset(long_value,'Q',130); long_value[130]=0;
    id.str.utf8=long_value; value.l=&id; bf_init_provider_shape(&m,value);
    assert(strstr(captured,"length=129 truncated=1") && !strstr(captured,"QQQQ"));
    id.kind=TL_K_OBJECT; bf_init_provider_shape(&m,value);
    assert(strstr(captured,"kind=non_string length=-1")); id.kind=TL_K_STRING;
    m.name="getISOCountryCode"; id.str.utf8="";
    for (int i=0;i<7;i++) bf_init_provider_shape(&m,value);
    captured[0]=0; bf_init_provider_shape(&m,value); assert(!captured[0]);
    captured[0]=0; cls.name="another/class"; bf_init_provider_shape(&m,value); assert(!captured[0]);
    puts("Initialize provider audit: bounded redacted shapes, exceptions and errno: PASS");
    return 0;
}
