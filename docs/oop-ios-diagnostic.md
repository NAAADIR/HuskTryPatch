# Opt-in out-of-place ARM64 diagnostic

This is a controlled development test, not the Brave Frontier backend. It is
compiled only when `HUSK_OOP_CFLAGS=-DHUSK_OOP_IOS_DIAG=1` and
`HUSK_OOP_SWIFT_FLAGS=HUSK_OOP_IOS_DIAG` are both set. Ordinary builds do not
expose the control or compile the diagnostic engine. The fixture is included as
a resource but is never loaded by an ordinary build.

The **OOP iOS diagnostic compile check** workflow runs on pushes to
`fix/brave-frontier-v20` and checks the fixture,
the diagnostic C for the iPhoneOS arm64 SDK, and its isolated Swift view. It
does not build an IPA. The **Build IPA** workflow's `oop_diagnostic` input is
off by default; when enabled it repeats those checks before the normal IPA
build and verifies the resource and diagnostic marker in the resulting IPA.
The workflows operate on committed repository content, not uncommitted local
files. Manual dispatch of the new workflow requires its registration on the
default branch. Do not run an IPA build until the compile-only check has passed.
Diagnostic packaging requires XcodeGen to include the new source files, and
checks for the real diagnostic marker and matching C/Swift build flags.

After an approved diagnostic IPA is built, install it with SideStore and enable
JIT using Husk's existing method. Before starting Android or an app, open
Settings → JIT & Sideload → Developer Diagnostic and tap **Run out-of-place
ARM64 test**. The test requires the debugger-granted mapping and a fresh native
allocator. It runs once per process; restart Husk before using the console
arena or starting a native app. Diagnostic builds refuse those starts after the
allocator is claimed; a normal build without the diagnostic flag is unchanged.

Search `Documents/husk.log` or `Documents/husk-native.log` for `HUSK-OOP-IOS`.
The prefix reports each requested stage and an error category on failure;
stages not reached are reported as `fail`. The diagnostic prefix does not
include addresses or game data. Existing JIT and crash logs are separate
runtime output and may contain addresses; review a full log before sharing it.
If the process stops while executing generated instructions, the prefix may end
at `native_entry=begin` without an `overall` line. Preserve the log from that
run; a process-killing OS or debugger fault cannot be converted into a safe C
error by this test.

The fixture is authenticated before loading. The real loader handles its two
relative relocations and one host import, but does not publish the library,
install an interpose or execute its constructors. Its executable image and
cache are distinct allocations from `tl_xmem`. The diagnostic claims ownership
against the separate console arena before allocating, and the existing JIT
allocator continues to coordinate its bottom reservation with QEMU. The claim
is retained until process exit because `tl_xmem` cannot free a bump allocation.
It is deliberately unavailable if a native app or the console arena is active.

This checks guest addresses, controlled BL/BLR/RET and one host-call signature;
it is single-threaded and uses checked fallback for memory and control flow.
It is not a general Android ABI, signal, permission, or self-modifying-code
implementation. Neither an iOS compile nor a device result has been observed
until the corresponding check is actually run.

## Real APK diagnostic

The same opt-in build adds a separate **Run real Brave Frontier ARM64 test**
button. It finds candidates through the installed app library's Android package
name `sg.gumi.bravefrontier`, then checks other installed APKs by hash if
needed. Filenames and labels are not used. It verifies the
full V20 APK SHA-256 and separately verifies both extracted ELF entries before
loading. It does not bundle the APK. If the package is absent or the checksum
differs, it fails before claiming executable memory. The work runs off the UI
thread. Start with JIT enabled and no game or console running; after either
diagnostic claims its allocator, fully restart Husk before another run or a
game. The claim is retained on failures after allocation as well.

The test opens the APK privately and uses the existing ELF mapper/relocator
with a private scope containing the APK's libc++_shared.so, Husk's bionic
resolver and the app-bundled ANGLE dylib. Neither library is published to the
normal loader registry. It rejects unknown dependencies, unresolved strong
imports, executable-segment relocations, TLS, mixed/copy pages, AOT and
IRELATIVE execution. Constructor and JNI initialization are not run. Only the
three previously verified functions execute. The existing debugger-granted xmem
aliases back the guest image and a distinct cache; all test writes are tracked.
The test fails if fewer than 64 MiB remain in the debugger-granted region.

`HUSK-OOP-REAL` reports each stage, `error_category`, guest native instruction
and block counts, and checked fallback instruction count. `unresolved_imports`
is -1 when symbol resolution was not reached; resolution stops at the first
missing strong import. A `fail` stage can mean that an earlier stage prevented
it from running. Search the log for this prefix; the new prefix contains no
addresses, request data or fingerprint values. A device crash during a native
entry may prevent the final status from being written.

The private iOS diagnostic path can also be exercised on Apple Silicon macOS:
`sh research/arm64-oop/run-real-ios-host.sh`. Set `HUSK_TEST_ANGLE_EGL` and
`HUSK_TEST_ANGLE_GLES` when macOS ANGLE is not installed at the paths in the
runner. This host result does not establish iOS ANGLE exports, actual device
memory availability, iPhoneOS compilation, or the server's rejection reason.
