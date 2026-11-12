#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
set -eu
cd "$(dirname "$0")/../.."
if [ "$(uname -s)" != Darwin ] || [ "$(uname -m)" != arm64 ]; then echo 'Apple Silicon macOS required' >&2; exit 1; fi
apk=${1:-' analysis/bfrevive-V20.apk'}
tmp=$(mktemp -d "${TMPDIR:-/tmp}/husk-oop-ios-host.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
python3 - "$apk" "$tmp/libgcore.so" <<'PY'
import hashlib, sys, zipfile
apk, dest = sys.argv[1:]
with open(apk, 'rb') as f: digest = hashlib.sha256(f.read()).hexdigest()
if digest != 'e571122a8706b2f815bf96e9b4b6549f6fc05c20bfe7d5890775ed7a2dfa3cd5':
    raise SystemExit('APK SHA-256 mismatch')
with zipfile.ZipFile(apk) as z, open(dest, 'wb') as f: f.write(z.read('lib/arm64-v8a/libgcore.so'))
print('V20 APK SHA-256 verified')
PY
bash tools/regress/build.sh research/arm64-oop/ios_diagnostic_host_test.c "$tmp/test" \
    -DHUSK_OOP_IOS_DIAG=1 -DHUSK_OOP_HOST_TEST=1 > "$tmp/build.log" 2>&1 || { cat "$tmp/build.log" >&2; exit 1; }
python3 - "$tmp/bad-fixture.bin" <<'PY'
import sys
data = bytearray(open('src/app/Husk/Resources/husk-oop-fixture.bin', 'rb').read())
data[0x1000] ^= 1
open(sys.argv[1], 'wb').write(data)
PY
"$tmp/test" bad-fixture "$tmp/bad-fixture.bin" "$tmp/libgcore.so"
"$tmp/test" arena-first src/app/Husk/Resources/husk-oop-fixture.bin "$tmp/libgcore.so"
"$tmp/test" smoke src/app/Husk/Resources/husk-oop-fixture.bin "$tmp/libgcore.so"
