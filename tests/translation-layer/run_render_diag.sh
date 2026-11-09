#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
cc -std=c11 -Wall -Wextra -Werror -I"$root/src/translation-layer-next" "$root/tests/translation-layer/render_diag_test.c" -o "$out/render_diag_test"
"$out/render_diag_test"
echo 'render diagnostic helper checks passed'
