#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
OUT=$(mktemp -d "${TMPDIR:-/tmp}/husk-current-test.XXXXXX")
trap 'rm -rf "$OUT"' EXIT
cc -std=c11 -Wall -Wextra -Werror -I"$ROOT/src/translation-layer-next" "$ROOT/tests/translation-layer/current_test.c" -o "$OUT/test"
"$OUT/test"
echo 'EGL current failure checks passed'
