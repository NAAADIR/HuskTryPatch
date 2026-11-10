#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
OUT=$(mktemp -d "${TMPDIR:-/tmp}/husk-bf-init.XXXXXX")
trap 'rm -rf "$OUT"' EXIT
clang -std=gnu11 -ffunction-sections -fdata-sections -pthread \
    -I"$ROOT/src/translation-layer-next" -I"$ROOT/src/translation-layer" \
    "$ROOT/tests/translation-layer/bf_init_gcore_diag_test.c" \
    -Wl,-dead_strip -Wl,-undefined,dynamic_lookup -framework CoreFoundation -o "$OUT/test"
"$OUT/test"
