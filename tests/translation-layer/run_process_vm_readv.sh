#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
OUT=$(mktemp -d "${TMPDIR:-/tmp}/husk-process-vm-readv.XXXXXX")
trap 'rm -rf "$OUT"' EXIT
clang -std=gnu11 -O1 -ffunction-sections -fdata-sections -pthread \
    -I"$ROOT/src/translation-layer-next" -I"$ROOT/src/translation-layer" \
    "$ROOT/tests/translation-layer/process_vm_readv_test.c" \
    "$ROOT/tests/translation-layer/process_vm_readv_libc_helper.c" \
    -Wl,-dead_strip -Wl,-undefined,dynamic_lookup -o "$OUT/test"
"$OUT/test"
clang -std=gnu11 -O1 -ffunction-sections -fdata-sections -pthread \
    -I"$ROOT/src/translation-layer-next" -I"$ROOT/src/translation-layer" \
    "$ROOT/tests/translation-layer/process_vm_readv_syscall_wrapper_test.c" \
    -Wl,-dead_strip -Wl,-undefined,dynamic_lookup -framework CoreFoundation -o "$OUT/syscall-wrapper-test"
"$OUT/syscall-wrapper-test"
