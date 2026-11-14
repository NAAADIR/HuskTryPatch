#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
set -eu
cd "$(dirname "$0")/../.."
out=$(mktemp -d "${TMPDIR:-/tmp}/husk-bf-shape.XXXXXX")
trap 'rm -rf "$out"' EXIT
clang -std=gnu11 -O1 -ffunction-sections -fdata-sections -pthread ${HUSK_TEST_SANITIZER_FLAGS:-} \
    -Isrc/translation-layer-next -Isrc/translation-layer \
    tests/translation-layer/bf_init_provider_shape_test.c \
    -Wl,-dead_strip -Wl,-undefined,dynamic_lookup -framework CoreFoundation -o "$out/test"
"$out/test"
# Check that the audit marker is compiled only for an explicit nonzero flag.
for flag in default zero enabled; do
    case "$flag" in
        default) define= ;;
        zero) define=-DHUSK_BF_INIT_AUDIT=0 ;;
        enabled) define=-DHUSK_BF_INIT_AUDIT=1 ;;
    esac
    clang -std=gnu11 -O1 -Isrc/translation-layer-next -Isrc/translation-layer \
        $define -c src/translation-layer-next/husk-tl-jni.c -o "$out/$flag.o"
    if strings "$out/$flag.o" | grep -F 'BF-INIT-SHAPE provider=' > /dev/null; then
        [ "$flag" = enabled ] || { echo 'provider audit unexpectedly enabled' >&2; exit 1; }
    else
        [ "$flag" != enabled ] || { echo 'provider audit marker missing' >&2; exit 1; }
    fi
done
echo 'Initialize provider audit: disabled by default and with flag=0: PASS'
