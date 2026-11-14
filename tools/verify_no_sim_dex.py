#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Fail closed unless a framework DEX implements no-SIM country as empty."""
import hashlib
import struct
import sys
import zlib

class DexError(ValueError):
    pass

def inspect(data):
    if len(data)<112 or data[:4]!=b'dex\n' or data[7]!=0:
        raise DexError('not a DEX file')
    if struct.unpack_from('<I',data,32)[0]!=len(data): raise DexError('DEX size mismatch')
    if hashlib.sha1(data[32:]).digest()!=data[12:32]: raise DexError('DEX signature mismatch')
    if zlib.adler32(data[12:])&0xffffffff!=struct.unpack_from('<I',data,8)[0]: raise DexError('DEX checksum mismatch')
    def uleb(pos):
        result=0
        for shift in range(0,35,7):
            v=data[pos]; pos+=1; result|=(v&127)<<shift
            if v<128: return result,pos
        raise DexError('invalid ULEB128')
    def pair(off): return struct.unpack_from('<II',data,off)
    ns,so=pair(0x38); nt,to=pair(0x40); np,po=pair(0x48)
    nm,mo=pair(0x58); nc,co=pair(0x60)
    def string(i):
        if i>=ns: raise DexError('invalid string index')
        pos=struct.unpack_from('<I',data,so+i*4)[0]; _,pos=uleb(pos)
        return data[pos:data.index(b'\0',pos)].decode('utf8')
    def typ(i):
        if i>=nt: raise DexError('invalid type index')
        return string(struct.unpack_from('<I',data,to+i*4)[0])
    def method(i):
        if i>=nm: raise DexError('invalid method index')
        return struct.unpack_from('<HHI',data,mo+i*8)
    matches=[]
    for i in range(nc):
        cls,_,_,_,_,_,cdata,_=struct.unpack_from('<8I',data,co+i*32)
        if typ(cls)!='Landroid/telephony/TelephonyManager;' or not cdata: continue
        pos=cdata; sizes=[]
        for _ in range(4): n,pos=uleb(pos); sizes.append(n)
        for _ in range(sizes[0]+sizes[1]): _,pos=uleb(pos); _,pos=uleb(pos)
        for count in sizes[2:]:
            idx=0
            for _ in range(count):
                delta,pos=uleb(pos); flags,pos=uleb(pos); code,pos=uleb(pos); idx+=delta
                owner,proto,name=method(idx)
                if typ(owner)!='Landroid/telephony/TelephonyManager;' or string(name)!='getSimCountryIso': continue
                if proto>=np: raise DexError('invalid prototype')
                _,ret,params=struct.unpack_from('<III',data,po+12*proto)
                if typ(ret)!='Ljava/lang/String;' or params!=0: continue
                if flags&0x108 or not code: raise DexError('method is static, native, or lacks code')
                registers,ins,_,tries,_,count_units=struct.unpack_from('<HHHHII',data,code)
                if registers<1 or ins!=1 or tries or count_units not in (3,4):
                    raise DexError('unexpected getSimCountryIso code shape')
                words=struct.unpack_from('<'+'H'*count_units,data,code+16)
                op=words[0]&255; reg=words[0]>>8
                if op==0x1a and count_units==3: index=words[1]
                elif op==0x1b and count_units==4: index=words[1]|(words[2]<<16)
                else: raise DexError('method does not directly return a string constant')
                if reg>=registers or words[-1]!=(reg<<8)|0x11 or string(index)!='':
                    raise DexError('getSimCountryIso does not return the empty string')
                matches.append((code,index,op,ns,so))
    if len(matches)!=1: raise DexError('expected exactly one no-argument SIM-country implementation')
    return matches[0]

def main(paths):
    if not paths: raise DexError('usage: verify_no_sim_dex.py DEX [DEX ...]')
    for path in paths:
        with open(path,'rb') as f: data=f.read()
        inspect(data)
        print(path+': getSimCountryIso() returns empty; DEX checksum/signature valid')

if __name__=='__main__':
    try: main(sys.argv[1:])
    except (DexError,IndexError,KeyError,UnicodeError,ValueError,struct.error,OSError) as e:
        print('DEX verification failed: '+str(e),file=sys.stderr); sys.exit(1)
