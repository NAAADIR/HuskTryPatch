#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Package clang's relocation-free ARM64 .text into a tiny controlled ET_DYN.

This is a fixture writer, not a general linker or loader. Three real ELF RELA
records are intentionally left for Husk's loader to resolve at runtime.
"""
import struct
import sys

obj = open(sys.argv[1], 'rb').read()
assert obj[:6] == b'\x7fELF\x02\x01'
assert struct.unpack_from('<H', obj, 18)[0] == 183
shoff = struct.unpack_from('<Q', obj, 40)[0]
shentsize, shnum, shstr = struct.unpack_from('<HHH', obj, 58)
sections = [struct.unpack_from('<IIQQQQIIQQ', obj, shoff + i * shentsize) for i in range(shnum)]
names = sections[shstr]
strings = obj[names[4]:names[4] + names[5]]
def name_at(table, off):
    return table[off:table.index(b'\0', off)].decode()
text_index = next(i for i, s in enumerate(sections) if name_at(strings, s[0]) == '.text')
text = sections[text_index]
assert not any(s[1] in (4, 9) and s[7] == text_index and s[5] for s in sections), 'text must have no unresolved relocations'
code = obj[text[4]:text[4] + text[5]]
assert len(code) < 0x1000
symtab = next(s for s in sections if s[1] == 2)
strsec = sections[symtab[6]]
strtab = obj[strsec[4]:strsec[4] + strsec[5]]
symbols = {}
for off in range(symtab[4], symtab[4] + symtab[5], symtab[9]):
    n, info, other, shndx, value, size = struct.unpack_from('<IBBHQQ', obj, off)
    if n and shndx == text_index:
        symbols[name_at(strtab, n)] = value
exports = ['fixture_entry', 'fixture_host_return', 'fixture_nested', 'fixture_marker',
           'fixture_middle', 'fixture_nested_return']
assert all(x in symbols for x in exports)

# The ELF is laid out in 16 KiB host-page-compatible segments.
image = bytearray(0x6000)
image[0x1000:0x1000 + len(code)] = code
dynstr = b'\0fixture_host\0' + b''.join(x.encode() + b'\0' for x in exports)
image[0x2100:0x2100 + len(dynstr)] = dynstr
entries = [bytes(24), struct.pack('<IBBHQQ', 1, 0x12, 0, 0, 0, 0)]
for x in exports:
    entries.append(struct.pack('<IBBHQQ', dynstr.index(x.encode()), 0x12, 0, 1, 0x1000 + symbols[x], 0))
image[0x2000:0x2000 + 24 * len(entries)] = b''.join(entries)
# A valid SysV hash table, with one bucket and a chain of all named symbols.
hash_words = [1, len(entries), 1] + [0] + list(range(2, len(entries))) + [0]
struct.pack_into('<' + 'I' * len(hash_words), image, 0x2200, *hash_words)
relas = [(0x4000, 1027, 0x4020), (0x4008, (1 << 32) | 257, 0),
         (0x4010, 1027, 0x1000 + symbols['fixture_nested'])]
for i, (offset, info, addend) in enumerate(relas):
    struct.pack_into('<QQq', image, 0x2300 + i * 24, offset, info, addend)
struct.pack_into('<Q', image, 0x4020, 37)
dynamic = [(4, 0x2200), (5, 0x2100), (10, len(dynstr)), (6, 0x2000),
           (7, 0x2300), (8, len(relas) * 24), (9, 24), (0, 0)]
for i, (tag, value) in enumerate(dynamic):
    struct.pack_into('<qQ', image, 0x4100 + 16 * i, tag, value)
ident = b'\x7fELF\x02\x01\x01' + bytes(9)
struct.pack_into('<16sHHIQQQIHHHHHH', image, 0, ident, 3, 183, 1, 0, 64, 0, 0, 64, 56, 3, 64, 0, 0)
for i, ph in enumerate([(1, 5, 0, 0, 0, 0x3000, 0x3000, 0x4000),
                        (1, 6, 0x4000, 0x4000, 0x4000, 0x2000, 0x8000, 0x4000),
                        (2, 6, 0x4100, 0x4100, 0x4100, len(dynamic)*16, len(dynamic)*16, 8)]):
    struct.pack_into('<IIQQQQQQ', image, 64 + i * 56, *ph)
with open(sys.argv[2], 'wb') as f:
    f.write(image)
print('packed controlled ELF with 3 unresolved runtime relocations')
