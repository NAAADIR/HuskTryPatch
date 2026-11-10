/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "../../src/translation-layer-next/husk-tl-ld.c"

static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;
static char logs[16384];
void tl_log_line(const char *fmt, ...)
{
    char line[512]; va_list ap;
    va_start(ap, fmt); vsnprintf(line, sizeof(line), fmt, ap); va_end(ap);
    pthread_mutex_lock(&log_lock);
    strncat(logs, line, sizeof(logs) - strlen(logs) - 1);
    strncat(logs, "\n", sizeof(logs) - strlen(logs) - 1);
    pthread_mutex_unlock(&log_lock);
}

static void short_string(unsigned char *out, const char *value)
{
    size_t n = strlen(value); assert(n <= 22);
    memset(out, 0, 24); out[0] = (unsigned char)(n * 2); memcpy(out + 1, value, n);
}

static void long_string(unsigned char *out, const char *value)
{
    size_t n = strlen(value); assert(n > 22);
    memset(out, 0, 24); out[0] = 1;
    memcpy(out + 8, &n, 8); memcpy(out + 16, &value, 8);
}

static void fake_set_message(void *state, const void *message)
{
    memcpy((unsigned char *)state + 0x20, message, 24); errno = EDOM;
}

static uintptr_t fake_read_param(void *self, int a, int b, const char *key, const char *value, bool flag)
{
    (void)self; (void)a; (void)b; (void)flag;
    if (!strcmp(key, "ZC0msu2L")) {
        unsigned char state[80] = {0}, message[24];
        if (strlen(value) > 22) long_string(message, value); else short_string(message, value);
        bf_corr_set_message(state, message);
    }
    errno = ERANGE;
    return 0x12345678;
}

struct fake_vector { const char *message; };
static uint64_t notice_sequence;
static bool change_during_check;
static uintptr_t fake_check(void *self)
{
    if (change_during_check) {
        unsigned char state[80] = {0}, message[24]; short_string(message, "different");
        bf_corr_set_message(state, message);
    }
    (void)self; notice_sequence = bf_corr_notice_sequence(); errno = ECHILD; return 17;
}
static uintptr_t fake_vector_parse(void *self, void *vector)
{
    (void)self; struct fake_vector *v = vector;
    assert(bf_corr_read_param(NULL, 0, 0, "3e9aGpus", "1", false) == 0x12345678);
    assert(bf_corr_read_param(NULL, 0, 0, "iPD12YCr", "2", false) == 0x12345678);
    assert(bf_corr_read_param(NULL, 0, 0, "ZC0msu2L", v->message, false) == 0x12345678);
    errno = EILSEQ; return 0x123456789abcdef0ULL;
}

static void *parse_thread(void *arg)
{
    errno = 0;
    assert(bf_corr_vector_parse(NULL, arg) == 0x123456789abcdef0ULL);
    assert(errno == EILSEQ);
    return NULL;
}

int main(int argc, char **argv)
{
    static const char rejection[] = "Please use the official app. Download it at bfrevive.net.";
    static const char payload[] = "{\"b5PH6mZa\":{\"ZC0msu2L\":\"Please use the official app. Download it at bfrevive.net.\",\"secret\":\"private-token\"}}";
    unsigned char item[72] = {0};
    short_string(item, "I9DyF2aU"); long_string(item + 24, payload);
    bf_corr_context transfer = bf_corr_async_item(item);
    assert(transfer.request == 3 && transfer.raw_match == 1);
    unsigned char frame_space[0x220] = {0};
    const unsigned char *item_pointer = item;
    memcpy(frame_space + 0x28, &item_pointer, sizeof(item_pointer));
    bf_corr_context frame_capture = bf_corr_worker_frame(frame_space + 0x220);
    assert(frame_capture.request == 3 && frame_capture.raw_match == 1);
    assert(bf_corr_worker_frame(NULL).raw_match == -1);
    short_string(item, "MfZyu1q9"); long_string(item + 24, payload);
    bf_corr_context initialize = bf_corr_async_item(item);
    assert(initialize.request == 1 && initialize.raw_match == 1 && transfer.seq != initialize.seq);
    assert(bf_corr_request("Fn1UzTo3", 8) == 2 && bf_corr_request("password", 8) == 0);
    assert(bf_corr_match("unrelated", 9) == 0 && bf_corr_match(NULL, 0) == -1);
    if (argc > 1) {
        FILE *f = fopen(argv[1], "rb"); assert(f);
        assert(!fseek(f, 0, SEEK_END)); long size = ftell(f); assert(size > 0x13ae000);
        rewind(f); unsigned char *bytes = malloc((size_t)size); assert(bytes);
        assert(fread(bytes, 1, (size_t)size, f) == (size_t)size); fclose(f);
        tl_lib lib = {0}; lib.rx = bytes; lib.ncode = 1;
        lib.code[0].start = 0x1390000; lib.code[0].end = 0x13ae000;
        assert(bf_corr_layout_ok(&lib));
        bytes[0x13972c4] ^= 1; assert(!bf_corr_layout_ok(&lib));
        free(bytes);
    }

    atomic_store(&bf_read_param_fn, (uintptr_t)fake_read_param);
    atomic_store(&bf_set_message_fn, (uintptr_t)fake_set_message);
    atomic_store(&bf_vector_parse_fn, (uintptr_t)fake_vector_parse);
    struct fake_vector first = {rejection}, second = {rejection};
    bf_corr_put(&first, transfer); bf_corr_put(&second, initialize);
    /* Identical responses, consumed in reverse and concurrently: pointer identity,
       not body content or last-request ordering, determines the association. */
    pthread_t a, b;
    assert(!pthread_create(&a, NULL, parse_thread, &second));
    assert(!pthread_create(&b, NULL, parse_thread, &first));
    pthread_join(a, NULL); pthread_join(b, NULL);
    char expected[128];
    snprintf(expected, sizeof(expected), "request=Transfer seq=%llu group=Message", (unsigned long long)transfer.seq);
    assert(strstr(logs, expected));
    snprintf(expected, sizeof(expected), "request=Initialize seq=%llu group=Message", (unsigned long long)initialize.seq);
    assert(strstr(logs, expected));
    assert(strstr(logs, "type=1 command=2 message_match=1 raw_match=1 state_populated=1"));
    assert(!strstr(logs, rejection) && !strstr(logs, "private-token"));
    bf_corr_context c; assert(!bf_corr_take(&first, &c));

    /* A matching parsed field must not be mistaken for a literal match in
       the pre-parser input (for example, JSON unicode escapes). */
    struct fake_vector escaped = {rejection};
    bf_corr_context no_literal = bf_corr_new(2, "escaped-json", 12);
    bf_corr_put(&escaped, no_literal);
    bf_corr_vector_parse(NULL, &escaped);
    assert(strstr(logs, "request=TransferCodeCheck"));
    assert(strstr(logs, "message_match=1 raw_match=0 state_populated=1"));

    /* No retained queue entry must fail closed, never borrow another request. */
    struct fake_vector missing = {"another private message"};
    assert(bf_corr_vector_parse(NULL, &missing) == 0x123456789abcdef0ULL);
    assert(strstr(logs, "request=Other seq=0 group=Message"));
    assert(!strstr(logs, "another private message"));
    bf_corr_context outer = bf_corr_new(3, payload, strlen(payload));
    bf_corr_current = &outer;
    assert(bf_corr_vector_parse(NULL, &missing) == 0x123456789abcdef0ULL);
    assert(bf_corr_current == &outer && !outer.saw_message);
    bf_corr_current = NULL;
    /* A notice is linked only if the shared state did not change during the
       check; any overlapping assignment invalidates the correlation. */
    bf_corr_context owner = bf_corr_new(1, payload, strlen(payload));
    unsigned char state[80] = {0}, message[24]; short_string(message, "message");
    bf_corr_current = &owner; bf_corr_set_message(state, message); bf_corr_current = NULL;
    atomic_store(&bf_check_message_fn, (uintptr_t)fake_check);
    assert(bf_corr_check_message(NULL) == 17 && notice_sequence == owner.seq && errno == ECHILD);
    change_during_check = true;
    assert(bf_corr_check_message(NULL) == 17 && notice_sequence == 0);
    bf_corr_reset();
    puts("BF correlation concurrency, boundary, redaction, and fallback passed");
}
