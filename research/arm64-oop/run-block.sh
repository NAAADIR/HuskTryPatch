#!/bin/sh
set -eu
cd "$(dirname "$0")/../.."
if [ "$(uname -s)" != Darwin ] || [ "$(uname -m)" != arm64 ]; then echo 'Apple Silicon macOS required' >&2; exit 1; fi
apk=${1:-' analysis/bfrevive-V20.apk'}
tmp=$(mktemp -d "${TMPDIR:-/tmp}/husk-bb.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
python3 - "$apk" "$tmp/libgame.so" <<'PY'
import hashlib, sys, zipfile
apk, out = sys.argv[1:]
with open(apk, 'rb') as f: digest = hashlib.sha256(f.read()).hexdigest()
if digest != 'e571122a8706b2f815bf96e9b4b6549f6fc05c20bfe7d5890775ed7a2dfa3cd5':
    raise SystemExit('APK SHA-256 mismatch')
with zipfile.ZipFile(apk) as z, open(out, 'wb') as f: f.write(z.read('lib/arm64-v8a/libgame.so'))
print('V20 APK SHA-256 verified')
import struct
with open(out, 'rb') as f: data = f.read()
u16 = lambda off: struct.unpack_from('<H', data, off)[0]
u64 = lambda off: struct.unpack_from('<Q', data, off)[0]
shoff, shentsize, shnum = u64(40), u16(58), u16(60)
sections = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * shentsize) for i in range(shnum)]
matches = []
for section in sections:
    if section[1] != 11 or not section[9]: continue
    strings = sections[section[6]]
    table = data[strings[4]:strings[4] + strings[5]]
    for off in range(section[4], section[4] + section[5], section[9]):
        name, info, other, index, address, size = struct.unpack_from('<IBBHQQ', data, off)
        if table[name:table.find(b'\0', name)] == b'_ZN17InitializeRequest12getRequestIDEv':
            matches.append((address, size))
if matches != [(0x13a50b8, 12)]: raise SystemExit('unexpected game leaf symbol')
print('verified InitializeRequest::getRequestID symbol and extent')
PY
clang -std=gnu11 -O2 -DBB_TESTING -Wall -Wextra -Werror -Wno-unused-function -ffunction-sections -fdata-sections \
 -Isrc/translation-layer -Isrc/translation-layer-next research/arm64-oop/block_engine.c \
 research/arm64-oop/arm64_oop.c research/arm64-oop/block_test.c research/arm64-oop/process_read_helper.c \
 -Wl,-dead_strip -Wl,-undefined,dynamic_lookup -o "$tmp/test"
"$tmp/test" "$tmp/libgame.so"
