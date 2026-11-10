/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Keep the real libc entry point in a separate translation unit. */
#include "../../src/translation-layer-next/husk-tl-bionic-sys.c"

long test_libc_process_vm_readv(int pid, const void *l, unsigned long ln,
                                const void *r, unsigned long rn, unsigned long flags)
{
    return b_process_vm_readv(pid, l, ln, r, rn, flags);
}
