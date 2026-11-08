#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
OUT=$(mktemp -d "${TMPDIR:-/tmp}/husk-string-web.XXXXXX")
trap 'rm -rf "$OUT"' EXIT
clang -std=c11 -Wall -Wextra -Werror -fsanitize=undefined -I"$ROOT/src/translation-layer-next" "$ROOT/tests/translation-layer/string_web_rect_test.c" -o "$OUT/test"
"$OUT/test"
