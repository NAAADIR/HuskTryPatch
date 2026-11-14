#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Record or verify the no-SIM source and both built framework DEX files."""
import hashlib
import json
import os
import pathlib
import struct
import sys
import tempfile

sys.dont_write_bytecode=True
from verify_no_sim_dex import inspect

MANIFEST='husk-framework-no-sim.json'

def digest(data): return hashlib.sha256(data).hexdigest()

def expected(source, full, core):
    files=[pathlib.Path(full),pathlib.Path(core)]
    if files[0].parent!=files[1].parent or files[0].name==files[1].name:
        raise ValueError('framework DEX files must be distinct and in one directory')
    dex={}
    for path in files:
        data=path.read_bytes(); inspect(data); dex[path.name]=digest(data)
    return {'version':1,'telephony_source_sha256':digest(pathlib.Path(source).read_bytes()),'dex_sha256':dex}

def process(mode,source,full,core):
    data=expected(source,full,core)
    path=pathlib.Path(full).parent/MANIFEST
    if mode=='write':
        fd,name=tempfile.mkstemp(prefix='.husk-framework-',dir=path.parent)
        try:
            with os.fdopen(fd,'w',encoding='utf-8') as f: json.dump(data,f,sort_keys=True); f.write('\n')
            os.replace(name,path)
        finally:
            if os.path.exists(name): os.unlink(name)
    elif mode=='verify':
        if json.loads(path.read_text(encoding='utf-8'))!=data:
            raise ValueError('framework DEX manifest does not match current source and DEX files')
    else: raise ValueError('mode must be write or verify')
    print('%s: full/core DEX semantics and source manifest verified'%path)

if __name__=='__main__':
    if len(sys.argv)!=5: raise SystemExit('usage: verify_framework_dex.py write|verify SOURCE FULL_DEX CORE_DEX')
    try: process(*sys.argv[1:])
    except (OSError,ValueError,IndexError,KeyError,UnicodeError,struct.error) as e:
        print('framework verification failed: '+str(e),file=sys.stderr); sys.exit(1)
