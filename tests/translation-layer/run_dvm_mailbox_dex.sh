#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
DEX=${1:?pass the path to a freshly built framework DEX}
OUT=$(mktemp -d "${TMPDIR:-/tmp}/husk-mailbox-dex.XXXXXX")
trap 'rm -rf "$OUT"' EXIT
if [ "$(uname -s)" = Darwin ]; then LINK='-Wl,-dead_strip -Wl,-undefined,dynamic_lookup'; else LINK='-Wl,--gc-sections -Wl,--unresolved-symbols=ignore-all'; fi
cc -std=gnu11 -ffunction-sections -fdata-sections -pthread -I"$ROOT/src/translation-layer-next" -I"$ROOT/src/translation-layer" "$ROOT/tests/translation-layer/dvm_mailbox_dex_test.c" $LINK -o "$OUT/test"
"$OUT/test" "$DEX"
echo 'compiled DEX mailbox DVM concurrency checks passed'
