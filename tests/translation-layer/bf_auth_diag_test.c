/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "../../src/translation-layer-next/husk-tl-ld.c"

static char last_log[512];
static char all_logs[8192];
void tl_log_line(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vsnprintf(last_log, sizeof(last_log), fmt, args);
    va_end(args);
    strncat(all_logs, last_log, sizeof(all_logs) - strlen(all_logs) - 1);
    strncat(all_logs, "\n", sizeof(all_logs) - strlen(all_logs) - 1);
}

static int force_calls, guest_calls, shutdown_calls, notice_calls;
static uintptr_t parse_original(void *self, void *response)
{
    assert(self == (void *)1 && response == (void *)2);
    return (uintptr_t)0x123456789abcdef0ULL;
}
static bool force_original(void *self) { assert(self == (void *)1); ++force_calls; return true; }
static void guest_original(void *self, void *obj) { assert(self == (void *)1 && obj == (void *)2); ++guest_calls; }
static void shutdown_original(void *self, void *obj) { assert(self == (void *)1 && obj == (void *)2); ++shutdown_calls; }
static void notice_original(void *self, int kind, const void *msg, bool flag, int value)
{ assert(self == (void *)1 && kind == 3 && msg == (void *)2 && flag && value == -1); ++notice_calls; }

int main(void)
{
    tl_lib game = {0};
    strcpy(game.soname, "libgame.so");
    elf_sym sym = { .st_value = 0x1c7b0d8 };
    const char *name = "_ZN21ServiceRequestManager18getForceUpdateFlagEv";
    uint64_t orig = (uintptr_t)force_original;
    assert(bf_diag_relocation(&game, &sym, name, R_GLOB_DAT, orig) == orig);
    sym.st_value++;
    assert(bf_diag_relocation(&game, &sym, name, R_JUMP_SLOT, orig) == orig);
    sym.st_value--;
    game.build = true;
    assert(bf_diag_relocation(&game, &sym, name, R_JUMP_SLOT, orig) == orig);
    game.build = false;
    bool (*force)(void *) = (void *)(uintptr_t)bf_diag_relocation(&game, &sym, name, R_JUMP_SLOT, orig);
    errno = EDOM;
    assert(force((void *)1) && force_calls == 1 && errno == EDOM);
    assert(strstr(last_log, "force_flag equals_one=1"));
    assert(bf_diag_relocation(&game, &sym, name, R_JUMP_SLOT, (uintptr_t)guest_original) == (uintptr_t)guest_original);
    assert(strstr(last_log, "skipped=another_image"));
    bf_diag_hook_report(&game);
    assert(strstr(all_logs, "hook_summary force=1 parse=0 guest=0 shutdown=0 notice=0"));
    /* Ensure the wrapper never truncates the unknown native return type to bool. */
    atomic_store_explicit(&bf_parse_fn, (uintptr_t)parse_original, memory_order_release);
    assert(bf_diag_parse((void *)1, (void *)2) == (uintptr_t)0x123456789abcdef0ULL);

    /* Vtable interception is restricted to exact slots and zero addends. */
    sym.st_value = 0x13919dc;
    const char *game_parse_name = "_ZN18GameResponseParser5parseEPKcP11RequestData";
    assert(bf_diag_abs_relocation(&game, &sym, game_parse_name, 0x27400d8, 1, orig) == orig);
    assert(bf_diag_abs_relocation(&game, &sym, game_parse_name, 0x27400e0, 0, orig) == orig);
    assert(bf_diag_abs_relocation(&game, &sym, game_parse_name, 0x27400d8, 0, orig) == (uintptr_t)bf_corr_game_parse);
    assert(!bf_corr_layout_ok(&game));

    sym.st_value = 0x1b8741c;
    void (*guest)(void *, void *) = (void *)(uintptr_t)bf_diag_relocation(&game, &sym,
        "_ZN10TitleScene25onGumiLiveLoginSuccessfulEPN7cocos2d8CCObjectE", R_GLOB_DAT, (uintptr_t)guest_original);
    guest((void *)1, (void *)2);
    assert(guest_calls == 1 && strstr(last_log, "guest_login_success"));

    sym.st_value = 0x1b850c0;
    void (*shutdown)(void *, void *) = (void *)(uintptr_t)bf_diag_relocation(&game, &sym,
        "_ZN10TitleScene27gameShutdownCallbackHandlerEPN7cocos2d8CCObjectE", R_GLOB_DAT, (uintptr_t)shutdown_original);
    shutdown((void *)1, (void *)2);
    assert(shutdown_calls == 1 && strstr(last_log, "shutdown_callback"));

    sym.st_value = 0x1608470;
    void (*notice)(void *, int, const void *, bool, int) = (void *)(uintptr_t)bf_diag_relocation(&game, &sym,
        "_ZN9GameScene17changeNoticeSceneEiRKNSt6__ndk112basic_stringIcNS0_11char_traitsIcEENS0_9allocatorIcEEEEbi",
        R_JUMP_SLOT, (uintptr_t)notice_original);
    notice((void *)1, 3, (void *)2, true, -1);
    assert(notice_calls == 1 && strstr(all_logs, "BF-AUTH-DIAG notice"));
    /* A new application session must not inherit pointers to unloaded code. */
    bf_diag_reset();
    bf_diag_hook_report(&game);
    assert(strstr(all_logs, "hook_summary force=0 parse=0 guest=0 shutdown=0 notice=0"));
    force_calls = 0;
    void *second = (void *)(uintptr_t)bf_diag_relocation(&game, &sym,
        "_ZN9GameScene17changeNoticeSceneEiRKNSt6__ndk112basic_stringIcNS0_11char_traitsIcEENS0_9allocatorIcEEEEbi",
        R_JUMP_SLOT, (uintptr_t)notice_original);
    assert(second == (void *)bf_diag_notice);
    ((void (*)(void *, int, const void *, bool, int))second)((void *)1, 3, (void *)2, true, -1);
    assert(notice_calls == 2);
    puts("BF diagnostic relocation guards and argument forwarding passed");
    return 0;
}
