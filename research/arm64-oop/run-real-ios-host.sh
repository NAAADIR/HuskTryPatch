#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
set -eu
cd "$(dirname "$0")/../.."
if [ "$(uname -s)" != Darwin ] || [ "$(uname -m)" != arm64 ]; then echo 'Apple Silicon macOS required' >&2; exit 1; fi
apk=${1:-' analysis/bfrevive-V20.apk'}
angle_dir='/Applications/Visual Studio Code.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Libraries'
egl=${HUSK_TEST_ANGLE_EGL:-"$angle_dir/libEGL.dylib"}
gles=${HUSK_TEST_ANGLE_GLES:-"$angle_dir/libGLESv2.dylib"}
if [ ! -f "$egl" ] || [ ! -f "$gles" ]; then echo 'Set HUSK_TEST_ANGLE_EGL and HUSK_TEST_ANGLE_GLES to ARM64 macOS ANGLE' >&2; exit 1; fi
tmp=$(mktemp -d "${TMPDIR:-/tmp}/husk-oop-real-ios-host.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
bash tools/regress/build.sh research/arm64-oop/real_ios_host_test.c "$tmp/test" \
    -DHUSK_OOP_IOS_DIAG=1 -DHUSK_OOP_HOST_TEST=1 > "$tmp/build.log" 2>&1 || { cat "$tmp/build.log" >&2; exit 1; }
"$tmp/test" bad "$tmp/missing.apk" "$egl" "$gles"
python3 - "$tmp/wrong.apk" <<'PY'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1], 'w') as z: z.writestr('not-the-game', 'x')
PY
"$tmp/test" bad "$tmp/wrong.apk" "$egl" "$gles"
"$tmp/test" arena-first "$apk" "$egl" "$gles"
"$tmp/test" synthetic-first "$apk" "$egl" "$gles"
"$tmp/test" missing-gl "$apk" "$egl" "$gles"
"$tmp/test" real "$apk" "$egl" "$gles"
