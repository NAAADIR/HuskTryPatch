/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Exercise the production raw dispatcher with real VM protections. */
#include "../../src/translation-layer-next/husk-tl-bionic-io.c"
#include <assert.h>

static int guest_errno;
int *tl_guest_errno_ptr(void) { return &guest_errno; }
void tl_set_guest_errno(int e) { guest_errno = e; }
int tl_errno_to_guest(int e) { return e; }
void tl_bf_gcore_diag_syscall(long nr, long result) { (void)nr; (void)result; }
void tl_log_line(const char *fmt, ...) { (void)fmt; }
void tl_note_once(const char *s) { (void)s; }
void *tl_bionic_find(const char *s) { (void)s; return NULL; }
long test_libc_process_vm_readv(int, const void *, unsigned long, const void *, unsigned long, unsigned long);

static long call(int pid, const void *l, unsigned long ln, const void *r, unsigned long rn, unsigned long flags)
{
    return tl_linux_syscall(pid, (long)l, (long)ln, (long)r, (long)rn, (long)flags, 270);
}

int main(void)
{
    size_t page = (size_t)getpagesize();
    char *src = mmap(NULL, page * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    char *dst = mmap(NULL, page * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    assert(src != MAP_FAILED && dst != MAP_FAILED);
    memcpy(src, "abcdefghij", 10);
    struct iovec l[] = {{dst, 3}, {dst + 3, 7}};
    struct iovec r[] = {{src, 5}, {src + 5, 5}};
    int pid = (int)tl_linux_syscall(0, 0, 0, 0, 0, 0, 172);
    assert(pid == getpid());
    assert(call(pid, l, 2, r, 2, 0) == 10 && !memcmp(dst, src, 10));
    /* Code pages are a distinct source from ordinary writable heap or stack. */
    struct iovec code_src = {(void *)(uintptr_t)&main, 16}, code_dst = {dst, 16};
    assert(call(pid, &code_dst, 1, &code_src, 1, 0) == 16);
    assert(!memcmp(dst, code_src.iov_base, 16));
    guest_errno = 77;
    assert(test_libc_process_vm_readv(pid, l, 2, r, 2, 0) == 10 && guest_errno == 77);
    assert(test_libc_process_vm_readv(pid, l, 2, r, 2, 1) == -1 && guest_errno == 22);
    assert(test_libc_process_vm_readv(pid + 1, l, 2, r, 2, 0) == -1 && guest_errno == 3);
    assert(test_libc_process_vm_readv(pid, (void *)1, 1, r, 2, 0) == -1 && guest_errno == 14);
    memset(dst, 0, 10);
    assert(call(pid, l, 1, r, 2, 0) == 3 && !memcmp(dst, "abc", 3));
    memset(dst, 0, 10);
    assert(call(pid, l, 2, r, 1, 0) == 5 && !memcmp(dst, "abcde", 5));
    assert(call(pid, l, 2, r, 2, 1) == -22);
    assert(call(pid, l, 1025, r, 2, 0) == -22);
    assert(call(pid, l, 2, r, 1025, 0) == -22);
    assert(call(pid, l, (unsigned long)-1, r, 2, 0) == -22);
    assert(call(pid, (void *)1, 1, r, 2, 0) == -14);
    assert(call(pid, l, 2, (void *)1, 1, 0) == -14);
    assert(call(pid + 1, l, 2, r, 2, 0) == -3);
    assert(call(pid + 1, NULL, 0, (void *)1, 9999, 0) == 0);
    assert(call(pid + 1, l, 2, NULL, 0, 0) == 0);
    assert(call(pid, NULL, 0, NULL, 0, 1) == -22);
    struct iovec empty = {(void *)1, 0};
    assert(call(pid + 1, &empty, 1, (void *)1, 1, 0) == 0);
    assert(call(pid + 1, l, 2, &empty, 1, 0) == 0);
    struct iovec huge[] = {{src, (size_t)LONG_MAX}, {src, 1}};
    assert(call(pid, huge, 2, r, 2, 0) == -22);
    assert(call(pid, l, 2, huge, 2, 0) == -22);
    struct iovec wrap = {(void *)(uintptr_t)(UINTPTR_MAX - 3), 8};
    assert(call(pid, &wrap, 1, r, 2, 0) == -14);
    struct iovec many[9];
    for (int i = 0; i < 9; ++i) many[i] = (struct iovec){dst + i, 1};
    assert(call(pid, many, 9, r, 2, 0) == 9 && !memcmp(dst, src, 9));
    for (int i = 0; i < 9; ++i) many[i] = (struct iovec){src + i, 1};
    struct iovec out9 = {dst, 9};
    assert(call(pid, &out9, 1, many, 9, 0) == 9 && !memcmp(dst, src, 9));
    assert(mprotect(src + page, page, PROT_NONE) == 0);
    assert(mprotect(dst + page, page, PROT_READ) == 0);
    struct iovec out = {dst, 8}, cross = {src + page - 4, 8};
    memcpy(src + page - 4, "wxyz", 4);
    assert(call(pid, &out, 1, &cross, 1, 0) == 4 && !memcmp(dst, "wxyz", 4));
    cross.iov_base = src + page;
    assert(call(pid, &out, 1, &cross, 1, 0) == -14);
    cross = (struct iovec){src, 8}; out.iov_base = dst + page - 4;
    assert(call(pid, &out, 1, &cross, 1, 0) == 4 && !memcmp(dst + page - 4, "abcd", 4));
    out.iov_base = dst + page;
    assert(call(pid, &out, 1, &cross, 1, 0) == -14);
    struct iovec split[] = {{src, 5}, {(void *)1, 5}};
    out = (struct iovec){dst, 10};
    assert(call(pid, &out, 1, split, 2, 0) == 5 && !memcmp(dst, "abcde", 5));
    /* iovec metadata must itself be copied safely, even across a protected page. */
    assert(call(pid, src + page - 8, 1, r, 2, 0) == -14);
    assert(call(pid, l, 2, src + page - 8, 1, 0) == -14);
    assert(munmap(src, page * 2) == 0 && munmap(dst, page * 2) == 0);
    puts("self process_vm_readv raw syscall: valid, partial and invalid cases passed");
    return 0;
}
