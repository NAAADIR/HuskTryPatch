#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Prove the DEX checker rejects stale semantics and damaged files."""
import hashlib
import pathlib
import struct
import sys
import zlib

sys.dont_write_bytecode=True
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[2]/'tools'))
import verify_no_sim_dex as check

if len(sys.argv)<2: raise SystemExit('usage: test_verify_no_sim_dex.py DEX [DEX ...]')
for path in sys.argv[1:]:
    data=bytearray(pathlib.Path(path).read_bytes())
    code,_,op,nstrings,strings=check.inspect(data)
    assert nstrings>1
    # The second string is nonempty in a valid sorted DEX with empty index 0.
    off=struct.unpack_from('<I',data,strings+4)[0]
    assert data[off]!=0
    struct.pack_into('<H',data,code+18,1)
    if op==0x1b: struct.pack_into('<H',data,code+20,0)
    data[12:32]=hashlib.sha1(data[32:]).digest()
    struct.pack_into('<I',data,8,zlib.adler32(data[12:])&0xffffffff)
    try: check.inspect(data)
    except check.DexError: pass
    else: raise AssertionError('non-empty SIM-country implementation accepted')
    data[12]^=1
    try: check.inspect(data)
    except check.DexError: pass
    else: raise AssertionError('corrupt DEX accepted')
    print(path+': stale return and damaged DEX rejected')
