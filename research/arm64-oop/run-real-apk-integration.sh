#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
set -eu
cd "$(dirname "$0")/../.."
if [ "$(uname -s)" != Darwin ] || [ "$(uname -m)" != arm64 ]; then echo 'Apple Silicon macOS required' >&2; exit 1; fi
apk=${1:-' analysis/bfrevive-V20.apk'}
angle_dir='/Applications/Visual Studio Code.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Libraries'
egl=${HUSK_TEST_ANGLE_EGL:-"$angle_dir/libEGL.dylib"}
gles=${HUSK_TEST_ANGLE_GLES:-"$angle_dir/libGLESv2.dylib"}
if [ ! -f "$egl" ] || [ ! -f "$gles" ]; then
    echo 'Set HUSK_TEST_ANGLE_EGL and HUSK_TEST_ANGLE_GLES to real macOS ARM64 ANGLE libraries' >&2; exit 1
fi
tmp=$(mktemp -d "${TMPDIR:-/tmp}/husk-oop-real-integration.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
python3 - "$apk" "$tmp/libgame.so" <<'PY'
import hashlib, sys, zipfile
apk, out = sys.argv[1:]
with open(apk, 'rb') as f: digest = hashlib.sha256(f.read()).hexdigest()
if digest != 'e571122a8706b2f815bf96e9b4b6549f6fc05c20bfe7d5890775ed7a2dfa3cd5':
    raise SystemExit('APK SHA-256 mismatch')
with zipfile.ZipFile(apk) as z, open(out, 'wb') as f: f.write(z.read('lib/arm64-v8a/libgame.so'))
print('V20 APK SHA-256 verified', flush=True)
PY
bash tools/regress/build.sh research/arm64-oop/real_apk_integration_test.c "$tmp/test" \
    -DHUSK_OOP_LOADER_TEST -DHUSK_OOP_REAL_TEST -Iresearch/arm64-oop research/arm64-oop/block_engine.c \
    > "$tmp/build.log" 2>&1 || { cat "$tmp/build.log" >&2; exit 1; }
"$tmp/test" "$apk" "$tmp/libgame.so" "$egl" "$gles"
