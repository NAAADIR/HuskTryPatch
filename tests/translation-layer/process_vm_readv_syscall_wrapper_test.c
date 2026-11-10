/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <assert.h>
#include <stdio.h>
#include "../../src/translation-layer-next/husk-tl-bionic.c"

static long answer;
long tl_linux_syscall(long a0, long a1, long a2, long a3, long a4, long a5, long nr)
{
    assert(nr == 270 && a0 == 11 && a1 == 22 && a2 == 33 && a3 == 44 && a4 == 55 && a5 == 66);
    return answer;
}
int main(void)
{
    answer = -14;
    assert(bionic_syscall(270, 11, 22, 33, 44, 55, 66) == -1 && *tl_guest_errno_ptr() == 14);
    answer = 7;
    assert(bionic_syscall(270, 11, 22, 33, 44, 55, 66) == 7 && *tl_guest_errno_ptr() == 14);
    puts("bionic syscall argument forwarding and errno conversion passed");
    return 0;
}
