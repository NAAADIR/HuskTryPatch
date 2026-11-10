/* BF v20-only diagnostic; included by husk-tl-ld.c after the loader types. */
#define BF_CORR_LIMIT (4u * 1024u * 1024u)
#define BF_CORR_SLOTS 128
typedef struct {
    uint64_t seq;
    unsigned request;
    int raw_match, message_match, state_populated, type, command;
    bool saw_message, has_type, has_command;
} bf_corr_context;
typedef struct { const void *vector; bf_corr_context context; } bf_corr_entry;
static pthread_mutex_t bf_corr_lock = PTHREAD_MUTEX_INITIALIZER;
static bf_corr_entry bf_corr_entries[BF_CORR_SLOTS];
static _Atomic(uint64_t) bf_corr_sequence;
static _Thread_local bf_corr_context *bf_corr_current;
typedef struct { uint64_t generation, seq; } bf_corr_check_context;
static _Thread_local bf_corr_check_context *bf_corr_check_current;
static uint64_t bf_corr_generation, bf_corr_state_sequence;
static unsigned bf_corr_setters;

/* The queue bridge reads a stack slot in one specific v20 worker. Do not
 * install that hook if any instruction establishing this layout differs. */
static bool bf_corr_layout_ok(const tl_lib *lib)
{
    static const struct { uint64_t va; uint32_t word; } required[] = {
        {0x13971b4, 0xa9057bfd}, {0x13971b8, 0x910143fd}, {0x13971bc, 0xd10743ff},
        {0x13972c0, 0xf86c796b}, {0x13972c4, 0xf90017eb},
        {0x1396ed4, 0xf9401508}, {0x1396ed8, 0xd63f0100},
        {0x1396f8c, 0xf9000a68}, {0x1396f90, 0x3d800260},
        {0x139703c, 0xf9000aa8}, {0x1397040, 0x3d8002a0},
        {0x139779c, 0x97e2adfd}, {0x1392448, 0xaa1803e0},
        {0x139244c, 0xaa1703e1}, {0x1392450, 0x97e33e5c},
        {0x13a50b8, 0xd0007c80}, {0x13a50bc, 0x91209800},
        {0x13ad718, 0xf0007c40}, {0x13ad71c, 0x910bd400},
        {0x13adb1c, 0xf0007c40}, {0x13adb20, 0x910e1400},
    };
    if (!lib || !lib->rx) return false;
    for (size_t i = 0; i < sizeof(required) / sizeof(required[0]); i++) {
        uint32_t word;
        if (!in_code(lib, required[i].va)) return false;
        memcpy(&word, (const void *)(uintptr_t)image_addr(lib, required[i].va), sizeof(word));
        if (word != required[i].word) return false;
    }
    return true;
}

static const char *bf_corr_class(unsigned n)
{
    static const char *const classes[] = { "Other", "Initialize", "TransferCodeCheck", "Transfer", "GuestLogin" };
    return n < sizeof(classes) / sizeof(classes[0]) ? classes[n] : classes[0];
}

static unsigned bf_corr_request(const char *p, size_t n)
{
    if (n != 8 || !p) return 0;
    if (!memcmp(p, "MfZyu1q9", 8)) return 1;
    if (!memcmp(p, "Fn1UzTo3", 8)) return 2;
    if (!memcmp(p, "I9DyF2aU", 8)) return 3;
    return 0;
}

/* Android libc++ in this exact ELF uses the little-endian short-string layout. */
static bool bf_corr_string(const void *object, const char **p, size_t *n)
{
    if (!object) return false;
    const unsigned char *s = object;
    if (!(s[0] & 1)) { *n = s[0] >> 1; *p = (const char *)(s + 1); return *n <= 22; }
    uint64_t length; const char *data;
    memcpy(&length, s + 8, sizeof(length)); memcpy(&data, s + 16, sizeof(data));
    if (!data || length > BF_CORR_LIMIT) return false;
    *p = data; *n = (size_t)length; return true;
}

static int bf_corr_match(const char *p, size_t n)
{
    static const char rejection[] = "Please use the official app. Download it at bfrevive.net.";
    if (!p || n > BF_CORR_LIMIT) return -1;
    const size_t len = sizeof(rejection) - 1;
    if (n < len) return 0;
    for (size_t i = 0; i <= n - len; i++)
        if (p[i] == rejection[0] && !memcmp(p + i, rejection, len)) return 1;
    return 0;
}

static void bf_corr_reset(void)
{
    pthread_mutex_lock(&bf_corr_lock);
    memset(bf_corr_entries, 0, sizeof(bf_corr_entries));
    bf_corr_generation = bf_corr_state_sequence = 0;
    bf_corr_setters = 0;
    pthread_mutex_unlock(&bf_corr_lock);
    atomic_store(&bf_corr_sequence, 0);
}

static bf_corr_context bf_corr_new(unsigned request, const char *p, size_t n)
{
    bf_corr_context c = { .seq = atomic_fetch_add(&bf_corr_sequence, 1) + 1,
        .request = request, .raw_match = bf_corr_match(p, n), .message_match = -1, .state_populated = -1 };
    return c;
}

static bf_corr_context bf_corr_async_item(const unsigned char *item)
{
    const char *id = NULL, *body = NULL; size_t id_len = 0, body_len = 0;
    bool valid_id = item && bf_corr_string(item, &id, &id_len);
    bool valid_body = item && bf_corr_string(item + 0x18, &body, &body_len);
    return bf_corr_new(valid_id ? bf_corr_request(id, id_len) : 0, valid_body ? body : NULL, body_len);
}

static bf_corr_context bf_corr_worker_frame(const unsigned char *frame)
{
    const unsigned char *item = NULL;
    if (frame) memcpy(&item, frame - 0x1f8, sizeof(item));
    return bf_corr_async_item(item);
}

static void bf_corr_put(const void *vector, bf_corr_context c)
{
    pthread_mutex_lock(&bf_corr_lock);
    size_t free_slot = BF_CORR_SLOTS;
    for (size_t i = 0; i < BF_CORR_SLOTS; i++) {
        if (bf_corr_entries[i].vector == vector) { free_slot = i; break; }
        if (!bf_corr_entries[i].vector && free_slot == BF_CORR_SLOTS) free_slot = i;
    }
    if (free_slot < BF_CORR_SLOTS) bf_corr_entries[free_slot] = (bf_corr_entry){vector, c};
    pthread_mutex_unlock(&bf_corr_lock);
}

static bool bf_corr_take(const void *vector, bf_corr_context *c)
{
    bool found = false;
    pthread_mutex_lock(&bf_corr_lock);
    for (size_t i = 0; i < BF_CORR_SLOTS; i++) {
        if (bf_corr_entries[i].vector != vector) continue;
        *c = bf_corr_entries[i].context;
        bf_corr_entries[i].vector = NULL;
        found = true; break;
    }
    pthread_mutex_unlock(&bf_corr_lock);
    return found;
}

static void bf_corr_report(const bf_corr_context *c)
{
    if (!c->saw_message) return;
    tl_log_line("BF-AUTH-CORR request=%s seq=%llu group=Message status=-1 type=%d command=%d message_match=%d raw_match=%d state_populated=%d",
        bf_corr_class(c->request), (unsigned long long)c->seq, c->has_type ? c->type : -1,
        c->has_command ? c->command : -1, c->message_match, c->raw_match, c->state_populated);
}

/* Synchronous parser: x2 is the request owned by the connector. */
static uintptr_t bf_corr_game_parse(void *self, const char *response, void *request)
{
    uintptr_t (*original)(void *, const char *, void *) = (void *)atomic_load(&bf_game_parse_fn);
    int saved = errno; unsigned cls = 0;
    if (request) {
        const uintptr_t *vtable = *(const uintptr_t *const *)request;
        if (vtable) {
            const void *fn = (const void *)vtable[5];
            tl_lib *lib = tl_ld_lib_of(fn);
            uintptr_t base = lib && !strcmp(lib->soname, "libgame.so") ? (uintptr_t)tl_ld_lib_base(lib) : 0;
            uintptr_t va = base ? (uintptr_t)fn - base : 0;
            if (va == 0x13a50b8) cls = 1;
            else if (va == 0x13ad718) cls = 2;
            else if (va == 0x13adb1c) cls = 3;
        }
    }
    size_t n = response ? strnlen(response, BF_CORR_LIMIT + 1) : 0;
    bf_corr_context c = bf_corr_new(cls, response, n), *previous = bf_corr_current;
    bf_corr_current = &c; errno = saved;
    uintptr_t result = original(self, response, request);
    saved = errno; bf_corr_current = previous; bf_corr_report(&c); errno = saved;
    return result;
}

/* Worker 0x13971a0 stores its _AsyncStruct* at fp-0x1f8. Its first two
 * libc++ strings are the request ID and response. At 0x139779c x0 is the
 * newly allocated _ResponseInfo's vector, later passed to ResponseData::parse.
 * Only this exact callsite is inspected; no packet bytes are retained. */
__attribute__((noinline)) static void bf_corr_vector_assign(void *vector, const void *first, const void *last)
{
    void (*original)(void *, const void *, const void *) = (void *)atomic_load(&bf_vector_assign_fn);
    const void *caller = __builtin_return_address(0);
    tl_lib *lib = tl_ld_lib_of(caller);
    uintptr_t base = lib && !strcmp(lib->soname, "libgame.so") ? (uintptr_t)tl_ld_lib_base(lib) : 0;
    bool selected = base && (uintptr_t)caller - base == 0x13977a0;
    bf_corr_context c = {0};
    int saved = errno;
    if (selected) {
        const void *const *own_frame = __builtin_frame_address(0);
        const unsigned char *frame = own_frame ? own_frame[0] : NULL;
        c = bf_corr_worker_frame(frame);
    }
    errno = saved; original(vector, first, last); saved = errno;
    if (selected) bf_corr_put(vector, c);
    errno = saved;
}

static uintptr_t bf_corr_vector_parse(void *self, void *vector)
{
    uintptr_t (*original)(void *, void *) = (void *)atomic_load(&bf_vector_parse_fn);
    int saved = errno; bf_corr_context c, *previous = bf_corr_current;
    bool found = bf_corr_take(vector, &c);
    if (!found) c = (bf_corr_context){ .raw_match = -1, .message_match = -1, .state_populated = -1 };
    bf_corr_current = &c;
    errno = saved; uintptr_t result = original(self, vector); saved = errno;
    bf_corr_current = previous; bf_corr_report(&c);
    errno = saved; return result;
}

static uintptr_t bf_corr_read_param(void *self, int a, int b, const char *key, const char *value, bool flag)
{
    uintptr_t (*original)(void *, int, int, const char *, const char *, bool) = (void *)atomic_load(&bf_read_param_fn);
    bf_corr_context *c = bf_corr_current; int saved = errno;
    if (c && key && value) {
        if (!strcmp(key, "ZC0msu2L")) {
            size_t n = strnlen(value, BF_CORR_LIMIT + 1);
            c->saw_message = true; c->message_match = bf_corr_match(value, n);
        } else if (!strcmp(key, "3e9aGpus") || !strcmp(key, "iPD12YCr")) {
            char *end = NULL; long n = strtol(value, &end, 10);
            if (end != value && *end == '\0' && n >= INT_MIN && n <= INT_MAX) {
                if (key[0] == '3') { c->type = (int)n; c->has_type = true; }
                else { c->command = (int)n; c->has_command = true; }
            }
        }
    }
    errno = saved; return original(self, a, b, key, value, flag);
}

static void bf_corr_set_message(void *self, const void *message)
{
    void (*original)(void *, const void *) = (void *)atomic_load(&bf_set_message_fn);
    int saved = errno; uint64_t generation, seq = bf_corr_current ? bf_corr_current->seq : 0;
    pthread_mutex_lock(&bf_corr_lock);
    generation = ++bf_corr_generation; bf_corr_setters++;
    pthread_mutex_unlock(&bf_corr_lock);
    errno = saved; original(self, message); saved = errno;
    if (bf_corr_current) {
        const char *p; size_t n;
        bf_corr_current->state_populated = bf_corr_string((const unsigned char *)self + 0x20, &p, &n) ? (n != 0) : -1;
    }
    pthread_mutex_lock(&bf_corr_lock);
    bf_corr_state_sequence = bf_corr_setters == 1 && generation == bf_corr_generation ? seq : 0;
    bf_corr_setters--; ++bf_corr_generation;
    pthread_mutex_unlock(&bf_corr_lock);
    errno = saved;
}

/* Snapshot the state before the game's check and invalidate it if any setter
 * overlaps the check. This ties a notice to the actual shared state without
 * using the last request or holding a lock around guest code. */
static uintptr_t bf_corr_check_message(void *self)
{
    uintptr_t (*original)(void *) = (void *)atomic_load(&bf_check_message_fn);
    int saved = errno; bf_corr_check_context c, *previous = bf_corr_check_current;
    pthread_mutex_lock(&bf_corr_lock);
    c.generation = bf_corr_generation;
    c.seq = bf_corr_setters ? 0 : bf_corr_state_sequence;
    pthread_mutex_unlock(&bf_corr_lock);
    bf_corr_check_current = &c; errno = saved;
    uintptr_t result = original(self); saved = errno;
    bf_corr_check_current = previous; errno = saved;
    return result;
}

static uint64_t bf_corr_notice_sequence(void)
{
    uint64_t seq = 0;
    pthread_mutex_lock(&bf_corr_lock);
    if (bf_corr_check_current && !bf_corr_setters &&
        bf_corr_check_current->generation == bf_corr_generation)
        seq = bf_corr_check_current->seq;
    pthread_mutex_unlock(&bf_corr_lock);
    return seq;
}
