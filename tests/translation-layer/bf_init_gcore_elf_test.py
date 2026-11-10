#!/usr/bin/env python3
"""Verify the v20 Initialize hook and raw syscall against the supplied APK."""
import struct
import sys
import zipfile

with zipfile.ZipFile(sys.argv[1]) as apk:
    game = apk.read("lib/arm64-v8a/libgame.so")
    core = apk.read("lib/arm64-v8a/libgcore.so")

def executable_word(data, va):
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    assert header[0][:6] == b"\x7fELF\x02\x01" and header[2] == 183
    for i in range(header[10]):
        kind, flags, offset, addr, _, size, _, _ = struct.unpack_from(
            "<IIQQQQQQ", data, header[5] + i * header[9])
        if kind == 1 and flags & 1 and addr <= va and va + 4 <= addr + size:
            return struct.unpack_from("<I", data, offset + va - addr)[0]
    raise AssertionError(f"no executable bytes at {va:#x}")

for va, word in {0x13a50dc: 0x1432b0ad, 0x2051390: 0x52800029,
                 0x20513d8: 0xd63f0140, 0x2051430: 0xd63f0120}.items():
    assert executable_word(game, va) == word, hex(va)
for va, word in {0x281c: 0xaa1903e1, 0x2820: 0x94000307,
                 0x4554: 0x528021c8, 0x4564: 0xd4000001}.items():
    assert executable_word(core, va) == word, hex(va)
assert b"libgcore.so\0gcore_tick\0Kv3dNq8Z\0R6wJm2Tf\0" in game
assert b"gcore_tick\0" in core
print("BF v20 Initialize gcore path and self-read syscall verified")
