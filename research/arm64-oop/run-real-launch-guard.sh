#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
set -eu
cd "$(dirname "$0")/../.."
tmp=$(mktemp -d "${TMPDIR:-/tmp}/husk-oop-launch-guard.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
bash tools/regress/build.sh research/arm64-oop/real_launch_guard_test.c "$tmp/test" \
    -DHUSK_OOP_IOS_DIAG=1 src/translation-layer-next/husk-tl-unity-app.c > "$tmp/build.log" 2>&1 || { cat "$tmp/build.log" >&2; exit 1; }
"$tmp/test"
