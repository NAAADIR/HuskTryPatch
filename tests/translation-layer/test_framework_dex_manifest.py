#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""A stale Java source or changed DEX must invalidate the build manifest."""
import pathlib
import shutil
import sys
import tempfile

sys.dont_write_bytecode=True
root=pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0,str(root/'tools'))
import verify_framework_dex as check

if len(sys.argv)!=3: raise SystemExit('usage: test_framework_dex_manifest.py FULL_DEX CORE_DEX')
with tempfile.TemporaryDirectory(prefix='husk-dex-manifest-') as temp:
    d=pathlib.Path(temp); src=d/'TelephonyManager.java'; full=d/'husk-framework.dex'; core=d/'husk-framework-core.dex'
    shutil.copyfile(root/'src/java-framework/src/android/telephony/TelephonyManager.java',src)
    shutil.copyfile(sys.argv[1],full); shutil.copyfile(sys.argv[2],core)
    args=(str(src),str(full),str(core))
    check.process('write',*args); check.process('verify',*args)
    original=src.read_bytes(); src.write_bytes(original+b'\n')
    try: check.process('verify',*args)
    except ValueError: pass
    else: raise AssertionError('stale source accepted')
    src.write_bytes(original)
    original=core.read_bytes(); core.write_bytes(original[:-1]+bytes([original[-1]^1]))
    try: check.process('verify',*args)
    except ValueError: pass
    else: raise AssertionError('damaged DEX accepted')
print('framework manifest: stale source and changed core DEX rejected')
