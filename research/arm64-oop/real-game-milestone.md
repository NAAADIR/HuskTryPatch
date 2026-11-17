# V20 real-game boundary, macOS ARM64

The APK SHA-256 is checked by both runners. The ELF dynamic symbol
`_ZN17InitializeRequest12getRequestIDEv` is at virtual address `0x13a50b8`,
size 12. Its instructions are ADRP x0, ADD x0, RET; the result is the guest
address at image virtual address `0x2337826`. It has no calls, loads, stores,
FP, TLS or dependency on its incoming `this` pointer. The exported symbol and
instructions justify a controlled integer-register ABI call, not any claim
about the safety of surrounding code or the contents of the request body.

`sh research/arm64-oop/run-block.sh` executes it in the hybrid engine in a
copy of the complete executable LOAD, on a separate native cache. It asserts
the dynamic symbol, instruction words, returned guest address and guest PC/LR,
and one native block plus one checked RET. It compares code and target reads
through the engine and production process_vm_readv helper with the original.
It then primes the block, changes an instruction through the controlled API,
checks invalidation and the changed result, checks SVC rejection, restores the
code and compares the full copied segment. The test is single-threaded and
does not establish coherence for writes outside the engine.

`sh research/arm64-oop/run-real-loader-probe.sh` extracts the real game and
attempts the strict existing OOP test loader in a separate process. It refuses
the library; in this isolated environment libc++_shared.so and several other
imports are unavailable, and the fixture guard rejects real-library features.
The earlier statement that this JIT load uses copied data pages was incorrect:
the logged 190-page copying came from the separate AOT build. This probe does
not relax its fixture restrictions or execute the game. Its absence of
dependency setup must not be confused with a production-device failure.

`sh research/arm64-oop/run-loader-integration.sh` separately passes real
loader relocation, guest reads, host gate and controlled invalidation for the
synthetic fixture. `sh research/arm64-oop/run-fingerprint.sh` separately shows
that the APK's gcore hash of the copied unmodified executable LOAD matches its
original and differs from the loader's AOT-rewritten output. Neither test proves
that the server verifies the fingerprint.

The next section records the subsequent loader-backed result. Do not simply
allow `dup` through the fixture guard: rewritten code currently redirects data
accesses to copied pages.

## Real loader-backed image on macOS ARM64

`sh research/arm64-oop/run-real-apk-integration.sh` now opens the verified APK
with `tl_ld_add_apk`, resolves the APK's `libc++_shared.so`, and loads an ARM64
macOS ANGLE through Husk's existing EGL resolver. Set `HUSK_TEST_ANGLE_EGL` and
`HUSK_TEST_ANGLE_GLES` to installed macOS ARM64 ANGLE libraries if the default
VS Code paths in the runner are unavailable. The result observed here was:

```
libc++_shared.so: 3529 relocations, 0 unresolved
libgame.so: 215996 relocations, 0 unresolved
real relocated game: leaf, relocated GLOB_DAT load, 16 KiB crossing guest load and process_vm_readv: PASS
original executable LOAD preserved; separate W^X cache; unsupported real FP instruction rejected: PASS
```

The new `HUSK_OOP_REAL_TEST` flag requires `HUSK_OOP_LOADER_TEST` and is only
for an isolated test process. It permits declared dependencies and constructor
metadata after loading dependencies but forbids running constructors. It
refuses missing strong imports immediately, failed or cyclic dependencies,
TLS, AOT, ARM32, duplicate data mappings, executable-LOAD relocations and
IRELATIVE resolver execution. BF diagnostic relocation hooks are not installed
in this test. It does not provide usable JNI or external call transitions.
The negative runner `run-real-apk-loader-probe.sh` without ANGLE fails at the
first missing GL import; this is expected. Passing both ANGLE environment
variables makes the probe attempt the complete relocation.

The original fixture guard refused any DT_NEEDED, init/init-array, TLS,
unresolved imports, AOT or duplicate mapping. The earlier probe also omitted
the APK from the library search and therefore could not find libc++_shared.so.
The real game has seven DT_NEEDED entries, an init array of 24128 bytes, no
PT_TLS, and 215996 supported ordinary relocation records; its dependency has
two system dependencies, an 8-byte init array, no PT_TLS and 3529 relocations.
The system dependencies use the production bionic resolver; GLES requires the
real ANGLE dylibs. Constructor pointers are relocated but not called.

The code and data PT_LOADs in this particular game are on separate 16 KiB
host pages: code ends at `0x26ca520`, data begins at `0x26cc090`. In JIT mode
`dup` is NULL. The loader populates and relocates its existing shared xmem
aliases: guest addresses use RX and writes use the RW alias. They name one
physical image, unlike an AOT dylib's separate data copies. Both guest image
and native cache have separate RX and RW aliases; the test checks their actual
host protections. The engine enforces a restricted 4 KiB logical page map;
the host protections operate at 16 KiB and do not enforce that logical map.
The test owns and serializes all image writes through `bb_write`, which
invalidates the cache. No claim is made for other writers, signal handlers,
host callbacks, arbitrary guest mmap/mprotect, or threads.

The test resolves and runs `InitializeRequest::getRequestID()` directly from
the relocated image (one native block, one checked RET), then
`__xmlStructuredErrorContext` (native ADRP; checked LDR and RET). The latter
loads its actual `R_AARCH64_GLOB_DAT` slot at `0x287b5c8`, checked against the
game's `xmlStructuredErrorContext` symbol. An `R_AARCH64_ABS64` slot is also
checked against the APK C++ library's real exported vtable and its addend.
The real `BattleUnit::getBattleTreasure()` LDR reads a controlled BSS value
straddling a 16 KiB boundary, and must match syscall 270's view. The test
checks guest PC/LR, both aliases' protections, original executable bytes,
invalidation, logical gap denial, and explicit rejection of a real FP
instruction. The backing file is read only to compare the original bytes;
the engine attaches to the loader image, not to that file copy.

This resolves the bounded JIT-backed test, not the general mixed-page or AOT
problem: the game happens to have no shared writable/executable host page.
Production integration would need a non-executable canonical guest mapping,
tracked writes from every source and synchronized invalidation, dependency and
host gates, per-thread register/TLS state, fault/unwind translation, and a
cache allocation strategy coordinated with the existing iOS arena. None of
those are established by this macOS test, and no conclusion follows about the
Initialize rejection or actual game performance.

## Production Dalvik-backed JNI_OnLoad and Java-to-guest natives (checkpoint)

`sh research/arm64-oop/run-real-jni-onload.sh ' analysis/bfrevive-V20.apk'`
(note the leading space in the directory name). It needs `build/java-runtime`,
taken exactly as `build-ipa.yml` does: `Payload/Husk.app/java-runtime/` from
the official Husk 3.4 release IPA (`Leviidev/Husk`, tag `3.4`).

It builds `real_constructor_test.c` with `HUSK_OOP_IOS_DIAG` (per-library OOP
mapping) plus `HUSK_OOP_PRODUCTION_DVM`. The older `run-real-constructors.sh`
uses the global `HUSK_OOP_REAL_TEST` mapping, under which *every* library is
OOP-mapped, so libcore's natives cannot load and no Java runtime is possible
there. In the new mode `tl_ld_oop_real_open` maps libgame.so and
libc++_shared.so privately first (it refuses once any library or APK is
registered), then Husk's production Dalvik runtime starts as `java_boot` does
(`husk_aosp_boot_jars`, `tl_dvm_start`, `tl_dvm_load_natives`) and
`tl_dvm_add_apk` adds the DEX. The APK is *not* given to `tl_ld_add_apk`, so a
Java `System.loadLibrary("game")` can never map a second, in-place libgame.
The HLE layer is not installed, as in production's Java-app mode. The whole
test runs on a 256 MiB-stack thread (interpreter recursion).

Observed on Apple Silicon macOS:

```
real_constructors attempted=3017 completed=3017 result=complete
real_jni_calls static=1 instance=1 last=com/tapjoy/TapjoyConnectCore.setPlugin(Ljava/lang/String;)V returned=0x10004
real_java_side_effect field=TapjoyConnectCore.Q value="cppStatic" same_jstring_as_guest_argument=yes
real_jni_adapter_tests passed=7/7 ...
real_jni_onload entered=yes completed=yes vm_stored=yes exception=none
real_java_to_guest native=Java_org_cocos2dx_lib_Cocos2dxHelper_nativeSetApkPath called=yes attach=1 utf_get=1 utf_release=1 guest_getApkPath_matches=yes
real_cxa registered=34747 invoked=189 completed=188 result=blocked   (known, separate)
```

`setPlugin` is `Q = plugin` in the APK bytecode (one `sput-object`); the field
read back through Husk's JNI is the identical jobj the guest made with
NewStringUTF. The final `real_jni_onload` counters include the adapter tests;
the genuine JNI_OnLoad counts are those in the earlier table (GetEnv 1,
FindClass 8, ... NewStringUTF 1).

### What was added

- `jni_gate.h`: one generic `Call[Static]<T>Method{V,A}` adapter for
  T in L Z B C S I J V. It decodes the guest AAPCS64 `va_list`
  (`__stack, __gr_top, __vr_top, __gr_offs, __vr_offs`) only with `bb_read`,
  converts by the method's `argk`, maps `L` through the token table, and calls
  Husk's own `Call…MethodA`, so dispatch is production `invoke()` (HLE `fn`,
  else `tl_dvm->invoke`). It refuses: pending exceptions, stale/unknown tokens,
  slot/return-kind and static/instance mismatches, float/double results (the
  domain returns only x0), and methods with neither HLE code nor bytecode
  (Husk would otherwise "return zero"). Also ExceptionCheck/Occurred/Clear,
  GetStringUTFChars/Release (copied into the guest heap; the guest never sees
  a host buffer), JavaVM AttachCurrentThread{,AsDaemon} (bound thread only,
  must yield Husk's env). Token table grew to 65536, never reused.
- Java-to-guest natives: `tl_dvm_set_foreign_natives` in `husk-tl-dvm.c`,
  compiled only under `HUSK_OOP_IOS_DIAG`. `find_jni` consults it last, after
  Husk's registrations and published libraries; `call_native` hands the shorty
  and typed jvalues to `jni_foreign_call`, which builds guest x0-x7/v0-v7 and
  8-byte stack slots, runs the domain (nested re-entry below the suspended SP
  via new `oop_domain_reentry_stack`), converts the result and frees the
  native frame's local tokens. Any guest stop throws `java.lang.InternalError`
  naming the native, gate and guest result. A second thread is refused.
- `oop_domain_call` now accepts caller-placed FP/SIMD and stack-argument
  calls; unknown ABI values are still refused (domain test updated).
- `tl_bionic_name_of` (diagnostic builds) names an unadapted host import.

### Shortest remaining path to a real startup (not done)

1. GL thread and threads in general. Cocos calls `Cocos2dxRenderer.nativeInit`
   / `nativeRender` on the GLSurfaceView thread; the gate and engine are bound
   to one thread with one guest stack/TLS. Needs per-thread guest stack + TLS,
   a serialized (or per-thread) engine, and guest `pthread_create`.
2. Host imports: libgame has 313 non-libc++ imports (68 GL, 23 pthread, ~220
   libc/libm/stdio/socket/dl). About 40 have adapters, all in the test file.
   Write them as one signature-table-driven adapter (per-import kinds:
   integer, float/double, read pointer, write pointer with length argument,
   string, callback, guest-pointer return), and add FP returns to the
   domain's host transition (`host_transition` writes only x0 today).
   Consider mapping the guest image in plain non-executable memory (only the
   code cache needs JIT memory): data pointers would then be writable host
   pointers and most adapters become checked pass-through.
3. Move the adapters from `real_constructor_test.c` into a production source
   and route `load_native_library` (`husk-tl-jni-hle.c`, System.loadLibrary)
   for the hash-verified libgame.so to it in an opt-in diagnostic build.
4. Performance: constructors ran 930217 native vs 1230740 checked-fallback
   instructions; a 60 fps game at that ratio is unmeasured and likely slow.

An iPhone IPA is not justified yet: on device the same path would stop at the
first GL-thread native, before the title screen and long before Initialize.

## Multithread OOP domain + reusable import bridge (checkpoint)

Two further pieces landed, both verified on Apple Silicon macOS against the
real relocated libgame.so, with no regression to the single-thread paths.

### Task A — thread-aware execution (engine + domain)

`block_engine.c` gained an opt-in execution lock (`bb_enable_threads`):
recursive mutex, held during translation and block execution, **released across
every host-gate callback**. The documented policy is: guest *instruction*
execution is serialized per engine (one thread computes at a time), while the
host calls where a guest thread actually blocks (pthread_mutex_lock, cond_wait)
run with the lock released, so two guest threads can be blocked/working at once
and cannot deadlock each other. The public bb_read/bb_write/bb_access/
bb_host_data_alias/bb_protect/bb_heap_* became thin locking wrappers over
`*_u` internals; the interpreter uses the `*_u` forms, and the recursive lock
makes the interpreter-holds-lock vs. gate-callback-reaches-API cases both safe.

`husk-oop-domain.c` moved its single-thread call-stack bookkeeping (depth,
suspended host_state/host_stack for re-entry) into **per-thread** context via a
`pthread_key_t`; the entry/host tables are guarded by `reg_lock` for lazy
runtime registration (the foreign-native path registers entries at run time).
`oop_domain_enable_threads` turns both on, once, after setup.

`sh research/arm64-oop/run-domain-thread.sh ' analysis/bfrevive-V20.apk'` runs
`domain_thread_test.c`: two host threads, each with its own guest stack and TLS
block, concurrently execute real leaf functions through one shared engine/image/
heap for 4000 iterations each. Result:

```
threads a_ok=1 b_ok=1 iters=4000 max_concurrent_in_domain=2
threads a_leaf=... b_leaf=... shared_image_result=1
threads a_tls=... b_tls=... tls_distinct=1 stacks_distinct=1
two-thread shared OOP domain on real libgame.so: PASS
```

It asserts: identical leaf result (shared image), per-thread TLS and stack
isolation, both threads simultaneously inside the domain, correct per-thread
round-trips through the shared heap, and clean teardown. A double/late
`enable_threads` is refused.

### Task B — reusable production import bridge

`src/translation-layer-next/husk-oop-imports.{c,h}` (opt-in diag/domain-test
builds) is a typed, table-driven registry that resolves imports from Husk's
real bionic (`tl_bionic_find`) and registers checked host-call gates. The first
family is the stateless memory/string set: memcpy, memmove (overlap-safe, with
the alias-to-one-address case handled), memset, memcmp, strlen, strnlen,
strcmp, strncmp, and the fortify `__*_chk` guards. Every byte touched is bounds
checked (`bb_access`/`bb_host_data_alias`/scan-to-NUL); host and guest pointer
representations stay distinct.

`real_constructor_test.c` now registers these through the bridge instead of its
private copies. The real constructor + JNI_OnLoad run routes **48,574** calls
through the bridge (`mem_bridge_imports=11`), JNI_OnLoad still completes, and
`Cocos2dxHelper.nativeSetApkPath` still round-trips. The normal no-flag Husk
build is unchanged (everything is behind `HUSK_OOP_IOS_DIAG`/`HUSK_OOP_DOMAIN_TEST`).

### Not done — exact blocker for Cocos nativeInit

Cocos runs `Cocos2dxRenderer.nativeInit` on the GL thread. The engine/domain now
permit that thread to enter, but the **JNI bridge (`jni_gate.h`) is still
single-thread**: it caches one thread's `host_env`, and its reference/UTF tables
and `jni_thread()` identity are bound to the owner thread. The next step is to
make the bridge per-thread: resolve the host JNIEnv live per call (`tl_jni_env()`
is already thread-local), lock the reference/UTF tables, and give each entering
thread its own env token + guest stack + TLS (reusing the per-thread domain
context already added). After that, the GL thread's native family (the ~68 GL
imports plus the remaining libc/pthread ones) must be added to the import bridge
and a real GL context bound on that thread. No nativeInit, and no iPhone build,
is justified until the per-thread JNIEnv bridge exists and that family is
present; the first on-device run would otherwise stop at the first GL-thread
JNI call.

## Per-thread JNI, nativeInit entered, production Java-app launch (checkpoint 2026-11-17)

### Done and verified (Apple Silicon macOS)

- `jni_gate.h` is now per-thread: one guest JavaVM, one guest JNIEnv view, TLS and
  stack per host thread (provisioned automatically on first Java->guest entry). The
  host env is resolved live (`tl_jni_env()`). The ref/method/UTF tables are locked,
  and the locks are never held across Java or guest code. Locals belong to their
  thread and native frame; slots are reused with a 12-bit generation. Thread exit
  releases that thread's state. New JNI surface: arrays, fields, NewObject,
  Push/PopLocalFrame, GetJavaVM, F/D returns.
- Domain: `oop_domain_thread_attach/owns/detach`, `oop_domain_return_fp` (v0),
  `oop_domain_set_errno` (per-thread guest errno at TPIDR+0xf00, synchronized
  around every host call).
- Engine: register-only FP/AdvSIMD and missing integer classes (SBFM/BFM, CCMP,
  ADC/SBC, DIV/shifts, CLZ/RBIT/REV, SMULH/UMULH) executed natively, each as its
  own one-instruction block. `sh research/arm64-oop/run-simd-native.sh`: 20/20 + 8/8.
- `husk-oop-imports.c`: GLES2 family (68/68), libc strings/math/time, strto*,
  printf family (guest-varargs formatter), `__errno`. 156 imports bridged.
- `run-real-jni-onload.sh`: `real_jni_threads ... PASS` (two real threads, 314
  Java calls from guest code, a held gate does not block the other thread, no
  deadlock).
- `HUSK_OOP_GL_THREAD=1`: real `nativeInit` entered on a GL thread (ANGLE
  pbuffer). It stops at a pending Java NPE: `Activity.getApplicationContext()` is
  null, because that mode has no Activity.
- Cocos teardown: once nativeInit has run, the pool manager exists before
  finalization and all 34750/34750 destructors complete. The earlier failure was
  lifecycle order, not memory.
- Production: `tl_jni_set_oop_library_claim` (husk-tl-jni-hle.c, HUSK_OOP_IOS_DIAG
  only) makes `System.loadLibrary` served by the OOP image; `tl_dvm_add_apk` is now
  idempotent per path.
- `HUSK_OOP_JAVAAPP=1 HUSK_OOP_JAVAAPP_SECS=120`: the real BraveFrontier
  activity starts, `loadLibrary("game")` is served by the OOP image, the activity
  calls nativeSetApkPath/nativeSetExternalAssetPath, and the render thread is ready
  (off-screen windows), 2 frames presented (black).

### Still to do (in order)

1. Java-app mode: find out why `Cocos2dxRenderer.nativeInit` is not called within
   120 s (does the activity create Cocos2dxGLSurfaceView? is it blocked, or slow
   in the DVM?). Read the full run.log (keep the tmp dir), and the logs of
   gl_main/AppRunner in husk-tl-dvm-android.c.
2. Once nativeInit runs on Husk's GL thread: follow the stops
   (`real_java_native_stop`) and add only the imports actually reached (likely
   stdio fopen/fread/fseek for the APK, pthread key/once/create, sscanf, wide
   chars, strtold).
3. Then nativeRender, and real frames in `frames/` (frame_files is still 0: check
   frame_every).
4. Move the setup out of the test (engine, protections, heap, TLS, mutex/heap/
   locale/cxa/signal gates) into a production module called by the loadLibrary
   claim (today the claim is served by an image already initialized by the test).
5. Teardown report for run10 (destructor 1 refused by a gate): print it with
   `report_guest_stop`.
6. Re-run the full regressions: run-block, run-domain-integration,
   run-domain-thread, run-real-apk-integration, run-simd-native, plus the normal
   no-OOP build.

No iPhone IPA is justified before nativeInit completes in the Java-app mode.

## Real Activity -> nativeInit complete -> nativeRender, first real frame (checkpoint 2026-11-18)

**Why nativeInit never ran in Java-app mode:** the runner used `husk-framework.dex` from the official Husk 3.4
IPA. This branch's GL loop (husk-tl-dvm-android.c, commit f0da509) calls `GLSurfaceView.huskHasSurface()`, which
exists only in the branch framework (`src/java-framework`). The log showed `UNIMPLEMENTED ... huskHasSurface()Z
(returning zero)`, so the render loop never made the app context and never called onSurfaceCreated. The fix: build
the branch framework exactly as build-ipa.yml does (JDK + R8 8.5.35, `src/java-framework/build.sh`; the DEX
verifier passes) into a runtime directory and pass that directory to the runner (2nd argument). build/java-runtime
was left as the official runtime (+ `*.official-3.4` backups); it should be rebuilt there the same way.

Run: `HUSK_OOP_JAVAAPP=1 HUSK_OOP_JAVAAPP_SECS=120 [HUSK_OOP_FRAME_EVERY=40 HUSK_OOP_FRAMES_COPY=dir
HUSK_OOP_LOG_COPY=file] sh research/arm64-oop/run-real-jni-onload.sh ' analysis/bfrevive-V20.apk' <branch java-runtime>`

Observed: renderer-register -> app ES2 context -> onSurfaceCreated -> **nativeInit completed** (real Activity,
Husk's GL thread). **nativeRender: 3427/3428 completed in 120 s (~28 fps)**, with ~3400 glClear, 322 glDrawArrays,
329 glBindTexture and 12 glTexImage2D. **Frame 80 (Husk's frame dump) shows the real "Alim" splash logo.**

Fixes made along the way (all production sources, under HUSK_OOP_IOS_DIAG / DOMAIN_TEST):
- Bridge families: files (stdio/fd/dir), rand*, strtok/strtok_r/strsep (implemented over guest memory),
  strerror(_r), the runtime family moved out of the test (heap, mutex/cond/rwlock/attr, keys, gettid,
  arc4random, sigset, getenv, strtoul, wcrtomb). memcpy/memset with n=0 are legal; overlapping memcpy has
  bionic arm64 (memmove) semantics.
- Domain: pthread_once with a guest routine (bionic 0/1/2 states); setjmp/longjmp on guest state (same guest
  call only; signal masks not saved); the ABI check covers x19-x29 (x18 is the platform register, used by
  this game's toolchain).
- Loader + bridge: host-bound data imports are recorded (`tl_ld_oop_data_imports`); `__stack_chk_guard` is
  rebound to a guest copy before any guest code runs (`__sF` x2 stays host-bound, used only as handles).
- Engine: sign-extending loads in every addressing form (PRFM is a no-op); a write invalidates the cache
  only if it touches an executable page; a 256-entry heap-block cache in range() (big speedup); a gate may
  redirect the PC only to executable guest code (longjmp).
- Tests updated to the new rules: domain_integration (x18 accepted), real_apk_integration (a BSS write does
  not invalidate), domain_fixture_a (FP16 FADD as the unsupported instruction).

Regressions passed: run-block, run-simd-native (20/20, 8/8, 5/5), run-domain-thread, run-domain-integration
(3 modes), run-real-apk-integration, no-OOP build (tools/regress/build.sh tools/javaapp-test.c),
run-real-jni-onload default mode (only the known teardown, `pool_before=absent`, as before).

### Still to do
1. Socket family: frame 169 of nativeRender stops at `socket(AF_INET6, SOCK_DGRAM, 0)` (the game's networking:
   socket/connect/send/recv/poll/select/getaddrinfo/fcntl/ioctl/inet_*). After that the frame is left in the
   middle and the following frames only clear (black). Do not alter auth/server validation.
2. Production launch module: engine/image/heap/TCB setup, constructors, JNI_OnLoad and the claim
   (`tl_jni_set_oop_library_claim`) are still called by the test. Production Husk must do this itself
   (opt-in) when the Java-app launch starts. Without it an IPA would use the in-place path.
3. Guest pthread_key destructors are not run at thread exit; sigsetjmp does not save the mask.
4. Performance: most instructions are still interpreted; ~28 fps on Mac with a light scene.

## Production OOP launch, networking, title screen (checkpoint 2026-11-18, evening)

**Production launch module:** `src/translation-layer-next/husk-oop-launch.{c,h}` (HUSK_OOP_IOS_DIAG).
- `husk_oop_launch_prepare()` runs from `husk-tl-unity-app.c` (ENGINE_JAVA; Brave Frontier is classified `.java`) before
  `java_boot`. It verifies the APK hash, claims the JIT arena (512→192 MiB), loads ANGLE, maps both images, sets up the
  engine, permissions, heap (≤256 MiB), TCB, domain, every bridge family, data-import rebinding, locale/cxa/thread
  gates, and the System.loadLibrary claim. If OOP is requested and prepare fails, the launch fails with the reason.
- The claim (`husk_oop_launch_claim`, on the Java thread that calls System.loadLibrary, as Android's dlopen) runs
  constructors once, then the JNI bridge, JNI_OnLoad once, foreign natives and threads.
- Opt-in: `HUSK_OOP_GAME=1`. On iOS: Settings > Developer Diagnostic > "Run Brave Frontier V20 out of place"
  (TLUnityView sets the env only with JIT; without JIT it refuses to launch). Build with `oop_diagnostic=true`.
- Mac validation of the production path: `HUSK_OOP_PRODUCTION=1 HUSK_OOP_JAVAAPP_SECS=180 sh
  research/arm64-oop/run-real-jni-onload.sh ' analysis/bfrevive-V20.apk'` (the runner builds nothing OOP itself).

**Result (production path, Mac):** constructors 3017/3017, JNI_OnLoad 0x10004, nativeInit completed, nativeRender
2464/2464, 108k glDrawArrays, 263 glTexImage2D, a guest network thread (pthread_create), socket+connect, the game's
"Connecting…" screen, then **the title screen with the Terms and Conditions dialog (v2.19.6.0)** (frame dump).
The terms WebView is blank (Husk's WebView, not OOP).

**Java runtime:** build-ipa.yml already builds the branch framework; it now also checks that husk-framework.dex
contains `GLSurfaceView.huskHasSurface`. The Mac runner refuses a runtime without it. `build/java-runtime` now has the
verified branch framework (`*.official-3.4` backups kept).

**Added along the way:** sockets (socket..getnameinfo, getaddrinfo copied into the guest heap), fortify `_chk` with the
guest's own bound (fixes an old bug: the host `__memcpy_chk` was called with 3 arguments), dedup by gate token,
pthread_create/join/detach/self/equal/exit, qsort/bsearch (guest comparator), struct tm (gmtime/localtime/_r, mktime,
strftime), sscanf/vsscanf, sigaction/signal (guest state only, host untouched, handlers not called), getpid & co,
nanosleep, engine: LD1-4/ST1-4 (multiple, single lane, replicate), LDR S/D/Q literal.

**iOS checks:** the host's x18 is never written (native blocks use x0/x9-x11/v0-v7 only; the guest's x18 lives in
bb_state); W^X via separate xmem aliases + sys_icache_invalidate (existing); data writes no longer invalidate,
code writes still do; the guest view's mprotect is tolerated if iOS refuses it. Not compiled for iOS here (no
iPhoneOS SDK on this Mac): `scripts/check_oop_ios.sh` (now covering launch/imports/jni-hle/dvm) or CI must do it.

### Still to do
1. iOS compilation (Xcode/CI) of the C and of the Swift changes (TLUnityView.swift, OOPDiagnostic.swift).
2. Device test: performance, JIT region size, GL context loss/backgrounding (not handled specifically).
3. Terms WebView content; tapping "I Agree" and the Initialize request (without touching the server).
4. Guest signal handlers are not delivered; pthread_key destructors not run; sigsetjmp without the mask.
