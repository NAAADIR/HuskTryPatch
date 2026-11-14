/* Use the actual Husk syscall dispatcher and self process_vm_readv implementation. */
#include "../../src/translation-layer-next/husk-tl-bionic-io.c"
static int guest_errno;
int *tl_guest_errno_ptr(void) { return &guest_errno; }
void tl_set_guest_errno(int e) { guest_errno = e; }
int tl_errno_to_guest(int e) { return e; }
void tl_bf_gcore_diag_syscall(long nr, long result) { (void)nr; (void)result; }
void tl_log_line(const char *fmt, ...) { (void)fmt; }
void tl_note_once(const char *s) { (void)s; }
void *tl_bionic_find(const char *s) { (void)s; return NULL; }
long prototype_read(void *dst, const void *src, size_t len) {
    struct iovec local = {dst, len}, remote = {(void *)src, len};
    return tl_linux_syscall(getpid(), (long)&local, 1, (long)&remote, 1, 0, 270);
}
long prototype_read_split(void *dst, const void *src, size_t left, size_t right) {
    struct iovec local[] = {{dst, left}, {(char *)dst + left, right}};
    struct iovec remote[] = {{(void *)src, left + right}};
    return tl_linux_syscall(getpid(), (long)local, 2, (long)remote, 1, 0, 270);
}
