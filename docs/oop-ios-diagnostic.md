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

After an approved diagnostic IPA is built, install it with SideStore and enable
JIT using Husk's existing method. Before starting Android or an app, open
Settings → JIT & Sideload → Developer Diagnostic and tap **Run out-of-place
ARM64 test**. The test requires the debugger-granted mapping and a fresh native
allocator. It runs once per process; restart Husk before using the console
arena. A normal native app can subsequently use the same `tl_xmem` allocator.

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
