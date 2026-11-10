#!/usr/bin/env python3
"""Read-only preflight against the exact ARM64 libgame.so used for the IPA."""
import struct
import sys

data = open(sys.argv[1], "rb").read()
h = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
assert h[0][:6] == b"\x7fELF\x02\x01" and h[2] == 183
phoff, phentsize, phnum = h[5], h[9], h[10]
shoff, shentsize, shnum = h[6], h[11], h[12]
segments = [struct.unpack_from("<IIQQQQQQ", data, phoff + i * phentsize) for i in range(phnum)]
sections = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shentsize) for i in range(shnum)]


def instruction(va):
    for typ, flags, offset, addr, _, size, _, _ in segments:
        if typ == 1 and flags & 1 and addr <= va and va + 4 <= addr + size:
            return struct.unpack_from("<I", data, offset + va - addr)[0]
    raise AssertionError(f"not in executable ELF segment: {va:#x}")


# These verify the guest frame size, work-item slot, request and response
# string stores, and transfer of the exact output vector to the callback.
words = {
    0x13971b4: 0xa9057bfd, 0x13971b8: 0x910143fd, 0x13971bc: 0xd10743ff,
    0x13972c0: 0xf86c796b, 0x13972c4: 0xf90017eb,
    0x1396ed4: 0xf9401508, 0x1396ed8: 0xd63f0100,
    0x1396f8c: 0xf9000a68, 0x1396f90: 0x3d800260,
    0x139703c: 0xf9000aa8, 0x1397040: 0x3d8002a0,
    0x139779c: 0x97e2adfd, 0x1392448: 0xaa1803e0,
    0x139244c: 0xaa1703e1, 0x1392450: 0x97e33e5c,
    0x13a50b8: 0xd0007c80, 0x13a50bc: 0x91209800,
    0x13ad718: 0xf0007c40, 0x13ad71c: 0x910bd400,
    0x13adb1c: 0xf0007c40, 0x13adb20: 0x910e1400,
}
for va, expected in words.items():
    assert instruction(va) == expected, f"worker layout mismatch at {va:#x}"

expected = {
    0x27400d8: (257, 0x13919dc, "_ZN18GameResponseParser5parseEPKcP11RequestData"),
    0x27482b0: (257, 0x13e1e2c, "_ZN15MessageResponse9readParamEiiPKcS1_b"),
    0x2854f08: (1026, 0x139b610, "_ZNSt6__ndk16vectorIN8picojson5valueENS_9allocatorIS2_EEE6assignIPS2_EENS_9enable_ifIXaasr21__is_forward_iteratorIT_EE5valuesr16is_constructibleIS2_NS_15iterator_traitsIS9_E9referenceEEE5valueEvE4typeES9_S9_"),
    0x2864620: (1026, 0x100773c, "_ZN12ResponseData5parseERNSt6__ndk16vectorIN8picojson5valueENS0_9allocatorIS3_EEEE"),
    0x284f3d0: (1026, 0x122a4fc, "_ZN12MessageState10setMessageENSt6__ndk112basic_stringIcNS0_11char_traitsIcEENS0_9allocatorIcEEEE"),
    0x284ff90: (1026, 0x1615e4c, "_ZN9GameScene20checkResponseMessageEv"),
}
found = set()
for sec in sections:
    if sec[1] != 4:
        continue
    symsec = sections[sec[6]]
    if symsec[1] != 11:
        continue
    strsec = sections[symsec[6]]
    strings = data[strsec[4]:strsec[4] + strsec[5]]
    for where, info, addend in struct.iter_unpack("<QQq", data[sec[4]:sec[4] + sec[5]]):
        if where not in expected:
            continue
        nameoff, _, _, _, value, _ = struct.unpack_from("<IBBHQQ", data, symsec[4] + (info >> 32) * symsec[9])
        name = strings[nameoff:strings.index(b"\0", nameoff)].decode("ascii")
        typ, va, symbol = expected[where]
        assert (info & 0xffffffff, value, name) == (typ, va, symbol)
        assert typ != 257 or addend == 0
        found.add(where)
assert found == set(expected), f"missing required relocations: {set(expected) - found}"
print("BF v20 correlation worker layout and six relocation slots verified")
