#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
set -eu
cd "$(dirname "$0")/../.."
if [ "$(uname -s)" != Darwin ] || [ "$(uname -m)" != arm64 ]; then echo 'Apple Silicon macOS required' >&2; exit 1; fi
tmp=$(mktemp -d "${TMPDIR:-/tmp}/husk-oop-loader.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
clang --target=aarch64-linux-android29 -c research/arm64-oop/loader_fixture.S -o "$tmp/fixture.o"
python3 research/arm64-oop/pack_loader_fixture.py "$tmp/fixture.o" "$tmp/fixture.so"
bash tools/regress/build.sh research/arm64-oop/loader_integration_test.c "$tmp/test" \
    -DHUSK_OOP_LOADER_TEST -Iresearch/arm64-oop research/arm64-oop/block_engine.c > "$tmp/build.log" 2>&1 || { cat "$tmp/build.log" >&2; exit 1; }
"$tmp/test" "$tmp/fixture.so"
