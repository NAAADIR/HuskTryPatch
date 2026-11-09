#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
OUT=$(mktemp -d "${TMPDIR:-/tmp}/husk-surface-test.XXXXXX")
trap 'rm -rf "$OUT"' EXIT
cc -std=c11 -Wall -Wextra -Werror -pthread -I"$ROOT/src/translation-layer-next" "$ROOT/tests/translation-layer/surface_size_test.c" -o "$OUT/test"
"$OUT/test"
echo 'surface size concurrency checks passed'
