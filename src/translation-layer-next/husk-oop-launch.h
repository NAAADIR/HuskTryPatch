/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Production out-of-place launch of the hash-verified Brave Frontier V20 APK
 * (opt-in, HUSK_OOP_IOS_DIAG builds only).
 *
 * husk_oop_launch_prepare() runs in Husk's Java launch before the Dalvik
 * runtime starts (no library or APK may be registered yet): it verifies the
 * APK, claims the JIT arena, maps libgame.so and libc++_shared.so privately,
 * attaches the block engine to the one guest image, sets guest permissions,
 * heap, TLS and the OOP domain, registers every import bridge family and
 * rebinds data imports. It then installs the System.loadLibrary claim.
 *
 * System.loadLibrary("game") (on the calling Java thread, as Android's dlopen)
 * runs the constructors once, opens the per-thread JNI bridge, runs the real
 * JNI_OnLoad once, installs the Java-to-guest native dispatch and enables
 * multithread entry (the GL thread is provisioned when it first calls a
 * native). Failure is explicit: the load fails; nothing is loaded in place.
 */
#pragma once
#ifdef HUSK_OOP_IOS_DIAG
#include <stdbool.h>
#include <stddef.h>

/* True when OOP execution is requested (HUSK_OOP_GAME=1) for this APK path.
 * The APK identity is verified by husk_oop_launch_prepare, not here. */
bool husk_oop_launch_requested(void);
bool husk_oop_launch_prepare(const char *apk, const char *angle_egl, const char *angle_gles, char *err, size_t errlen);
/* Status for logs and the device report. */
typedef struct {
    bool prepared, constructors_done, jni_onload_done, threads_enabled;
    unsigned constructors_attempted, constructors_completed, loadlibrary_claims;
    int jni_onload_version;
    size_t heap_bytes, xmem_used;
    char failure[200];
} husk_oop_launch_status;
void husk_oop_launch_get_status(husk_oop_launch_status *out);
/* The bridge objects, for diagnostics (struct jni_gate / struct oop_imports). */
#include <stdint.h>
bool husk_oop_launch_views(const uint8_t **game, size_t *game_size, const uint8_t **cpp, size_t *cpp_size);
struct jni_gate *husk_oop_launch_jni(void);
struct oop_imports *husk_oop_launch_imports(void);
#endif
