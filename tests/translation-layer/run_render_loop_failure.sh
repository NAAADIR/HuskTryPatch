#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
OUT=$(mktemp -d "${TMPDIR:-/tmp}/husk-gl-loop.XXXXXX")
trap 'rm -rf "$OUT"' EXIT
if [ "$(uname -s)" = Darwin ]; then
    LINK='-Wl,-dead_strip -Wl,-undefined,dynamic_lookup'
else
    LINK='-Wl,--gc-sections -Wl,--unresolved-symbols=ignore-all'
fi
cc -std=gnu11 -ffunction-sections -fdata-sections -pthread -I"$ROOT/src/translation-layer-next" -I"$ROOT/src/translation-layer" "$ROOT/tests/translation-layer/render_loop_failure_test.c" $LINK -o "$OUT/test"
"$OUT/test"
echo 'render loop EGL failure checks passed'
