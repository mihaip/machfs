#!/usr/bin/env python3
"""Seeded interoperability checks against original hfsutils 3.2.6 and fsck_hfs.

No dependencies beyond machfs's dependencies and Python's standard library.
Pass --libhfs /absolute/path/to/libhfs.dylib (or .so).
All images are newly created under --output. libhfs is called directly, so no
~/.hcwd mount state is read or written. machfs imports always use this checkout.
"""
import argparse
import ctypes as C
import hashlib
import json
import os
from pathlib import Path
import plistlib
import random
import struct
import subprocess
import sys

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
import machfs
from machfs import Volume, Folder, File, btree
from machfs._names import name_key

assert Path(machfs.__file__).resolve().parent == REPO / 'machfs'


class Location(C.Structure):
    _fields_ = [('v', C.c_short), ('h', C.c_short)]


class FileInfo(C.Structure):
    _fields_ = [('dsize', C.c_ulong), ('rsize', C.c_ulong),
                ('type', C.c_char * 5), ('creator', C.c_char * 5)]


class DirInfo(C.Structure):
    _fields_ = [('valence', C.c_ushort), ('rect', C.c_short * 4)]


class Info(C.Union):
    _fields_ = [('file', FileInfo), ('dir', DirInfo)]


class Entry(C.Structure):
    _fields_ = [('name', C.c_char * 32), ('flags', C.c_int),
                ('cnid', C.c_ulong), ('parid', C.c_ulong),
                ('crdate', C.c_long), ('mddate', C.c_long), ('bkdate', C.c_long),
                ('fdflags', C.c_short), ('fdlocation', Location), ('u', Info)]


class LibHFS:
    def __init__(self, path):
        self.lib = C.CDLL(str(path))
        p, s, i, u = C.c_void_p, C.c_char_p, C.c_int, C.c_ulong
        signatures = {
            'mount': (p, [s,i,i]), 'umount': (i,[p]),
            'format': (i,[s,i,i,s,C.c_uint,C.POINTER(u)]),
            'mkdir': (i,[p,s]), 'create': (p,[p,s,s,s]), 'open': (p,[p,s]),
            'close': (i,[p]), 'setfork': (i,[p,i]),
            'read': (u,[p,p,u]), 'write': (u,[p,p,u]),
            'seek': (u,[p,C.c_long,i]), 'delete': (i,[p,s]),
            'stat': (i,[p,s,C.POINTER(Entry)]),
            'setattr': (i,[p,s,C.POINTER(Entry)]),
        }
        for name, (result, args) in signatures.items():
            fn = getattr(self.lib, 'hfs_' + name)
            fn.restype, fn.argtypes = result, args
            setattr(self, name, fn)

    def check(self, result):
        if result is None or result == -1 or result == C.c_ulong(-1).value:
            raise RuntimeError(C.c_char_p.in_dll(self.lib, 'hfs_error').value)
        return result

    def compare(self, path, volume):
        vol = self.check(self.mount(os.fsencode(path), 0, 0))
        try:
            for parts, obj in volume.iter_paths():
                name = (':' + ':'.join(parts)).encode('mac_roman')
                entry = Entry(); self.check(self.stat(vol, name, C.byref(entry)))
                if isinstance(obj, Folder):
                    assert entry.flags & 1, parts
                    assert entry.u.dir.valence == len(obj), parts
                    continue
                assert not entry.flags & 1, parts
                assert bool(entry.flags & 2) == obj.locked, parts
                assert C.string_at(C.addressof(entry.u.file)+FileInfo.type.offset,4) == obj.type, parts
                assert C.string_at(C.addressof(entry.u.file)+FileInfo.creator.offset,4) == obj.creator, parts
                assert entry.fdflags & 0xffff == obj.flags, parts
                assert (entry.fdlocation.h, entry.fdlocation.v) == (obj.x, obj.y), parts
                handle = self.check(self.open(vol, name))
                try:
                    for fork, expected in enumerate((obj.data, obj.rsrc)):
                        self.check(self.setfork(handle, fork))
                        buf = C.create_string_buffer(len(expected)+1)
                        got = self.check(self.read(handle, buf, len(buf)))
                        assert got == len(expected) and buf.raw[:got] == expected, (parts, fork)
                finally:
                    self.check(self.close(handle))
        finally:
            self.check(self.umount(vol))

    def write_file(self, vol, name, data, rsrc=b''):
        handle = self.check(self.create(vol, name, b'TEST', b'MHFS'))
        try:
            for fork, payload in enumerate((data, rsrc)):
                self.check(self.setfork(handle, fork))
                assert self.check(self.write(handle, payload, len(payload))) == len(payload)
        finally:
            self.check(self.close(handle))


def fsck(path):
    result = subprocess.run(['hdiutil', 'attach', '-plist', '-imagekey',
        'diskimage-class=CRawDiskImage', '-nomount', '-readonly', str(path)],
        capture_output=True, check=True, timeout=60)
    entities = plistlib.loads(result.stdout)['system-entities']
    devices = [e['dev-entry'] for e in entities if 'dev-entry' in e]
    try:
        device = next((e['dev-entry'] for e in entities
            if e.get('potentially-mountable') and 'dev-entry' in e), devices[-1])
        result = subprocess.run(['/sbin/fsck_hfs', '-fn', device],
            capture_output=True, text=True, timeout=60)
        path.with_suffix('.fsck.txt').write_text(result.stdout + result.stderr)
        assert result.returncode == 0, (path.name, result.stdout, result.stderr)
    finally:
        subprocess.run(['hdiutil', 'detach', devices[0]],
            capture_output=True, check=True, timeout=60)


def snapshot(v):
    rows = []
    for parts, obj in v.iter_paths():
        common = (parts, obj.flags, obj.crdate, obj.mddate, obj.bkdate)
        if isinstance(obj, File):
            common += (obj.type,obj.creator,obj.locked,obj.x,obj.y,
                       hashlib.sha256(obj.data).hexdigest(),hashlib.sha256(obj.rsrc).hexdigest())
        rows.append(common)
    return sorted(rows)


def clear_legacy_start_blocks(source, destination):
    """Normalize only hfsutils' obsolete filStBlk/filRStBlk fields.

    Modern Apple fsck requires zero here. Keep the original independent
    image, extents, B-trees, allocation bitmap, and all fork data unchanged.
    """
    data = bytearray(source.read_bytes())
    blocksize = struct.unpack_from('>L', data, 1044)[0]
    start = struct.unpack_from('>H', data, 1052)[0]*512
    extents = struct.unpack_from('>6H', data, 1174)
    changed = 0
    for first, count in zip(extents[::2], extents[1::2]):
        for node in range(start+first*blocksize, start+(first+count)*blocksize,512):
            if data[node+8] != 255: continue
            records = struct.unpack_from('>H',data,node+10)[0]
            for i in range(records):
                rec=node+struct.unpack_from('>H',data,node+510-2*i)[0]
                val=rec+((data[rec]+2)&~1)
                if data[val] != 2: continue
                for offset in (24,34):
                    if data[val+offset:val+offset+2] != bytes(2): changed += 1
                    data[val+offset:val+offset+2]=bytes(2)
    assert changed
    destination.write_bytes(data)
    return changed


def random_volume(seed, count):
    rng = random.Random(seed)
    v = Volume(); v.name = 'Shakedown'; v.crdate = 0xc0000000
    v.mddate = v.crdate+1; v.bkdate = v.crdate+2
    folders = [v]
    alphabet = 'aAzZ019 !_-éàÄæøßΩÿŸ '
    for i in range(count):
        parent = rng.choice(folders)
        # A unique numeric prefix keeps generated HFS names valid and distinct;
        # name-equivalence collisions have their own exhaustive differential test.
        name = '%04d-' % i + ''.join(rng.choice(alphabet) for _ in range(rng.randrange(1,27)))
        if rng.randrange(6) == 0:
            obj = Folder(); folders.append(obj)
        else:
            obj = File(); obj.type=b'TEST'; obj.creator=b'MHFS'
            for fork in ('data','rsrc'):
                length = rng.choice([0,1,2,511,512,513,1023,1024,1025,4095,4096,4097])
                setattr(obj,fork,rng.randbytes(length))
            obj.locked = bool(rng.randrange(2)); obj.flags = rng.choice([0,0x4000,0x0400,0x0100])
            obj.x = rng.randrange(-32768,32768); obj.y = rng.randrange(-32768,32768)
        obj.crdate=v.crdate; obj.mddate=v.mddate; obj.bkdate=v.bkdate
        parent[name]=obj
    return v


def independent_image(lib, path):
    # Deliberately interleave growth of both forks with other files to force
    # >3 extents, including an indexed (nontrivial) overflow tree.
    with path.open('wb') as f: f.truncate(8*1024*1024)
    lib.check(lib.format(os.fsencode(path),0,0,b'Independent',0,None))
    vol=lib.check(lib.mount(os.fsencode(path),0,1))
    data = bytearray(); rsrc = bytearray()
    try:
        lib.check(lib.mkdir(vol,b':folder'))
        lib.write_file(vol,b':folder:fragmented',b'')
        for i in range(48):
            handle=lib.check(lib.open(vol,b':folder:fragmented'))
            try:
                for fork, expected in enumerate((data,rsrc)):
                    lib.check(lib.setfork(handle,fork)); lib.check(lib.seek(handle,0,2))
                    payload=bytes((j+i+fork)%256 for j in range(4096+i))
                    assert lib.check(lib.write(handle,payload,len(payload)))==len(payload)
                    expected.extend(payload)
            finally: lib.check(lib.close(handle))
            lib.write_file(vol,(':blocker%03d'%i).encode(),bytes(4096))
        entry=Entry(); lib.check(lib.stat(vol,b':folder:fragmented',C.byref(entry)))
        entry.flags |= 2
        lib.check(lib.setattr(vol,b':folder:fragmented',C.byref(entry)))
    finally: lib.check(lib.umount(vol))
    v=Volume();v.read(path.read_bytes())
    f=v['folder','fragmented']
    assert f.data == data and f.rsrc == rsrc and f.locked
    lib.compare(path,v)
    raw=path.read_bytes()
    blocksize=struct.unpack_from('>L',raw,1044)[0]
    start=struct.unpack_from('>H',raw,1052)[0]*512
    first,count=struct.unpack_from('>HH',raw,1158)
    overflow=raw[start+first*blocksize:start+(first+count)*blocksize]
    records=list(btree.dump_btree(overflow))
    assert len(records)>16, 'Fragmentation did not exercise enough overflow records'
    assert struct.unpack_from('>H',overflow,14)[0]>1, 'Overflow tree did not gain an index'
    assert {rec[1] for rec in records} == {0,255}, 'Both forks need overflow extents'
    return v


def geometry_checks(args, lib):
    cases=[]
    for align in (512,2048):
        for size in (400*1024,2**25-512,2**25,2**25+512,2**26,2**31,2**32-512,2**32):
            v=Volume();v.name='Geometry';v['probe']=File();v['probe'].data=b'geometry'
            path=args.output/('geometry-%d-%d.hfs'%(size,align))
            left,hole,right=v.write(size,align=align,desktopdb=False,sparse=True)
            with path.open('wb') as f:
                f.write(left);f.seek(hole,1);f.write(right)
            # Original libhfs deliberately refuses volumes smaller than 800K.
            if size >= 800*1024: lib.compare(path,v)
            if args.fsck: fsck(path)
            cases.append({'size':size,'align':align,'status':'passed',
                'hfsutils':'passed' if size >= 800*1024 else 'unsupported: below 800K'})
            print('PASS geometry',size,align,flush=True)
    return cases


def reference_checks(args, lib):
    cases=[]
    for source in args.reference:
        original=source.read_bytes()
        raw=original
        if raw[82:84]==b'\x01\x00' and raw[1108:1110]==b'BD':
            raw=raw[84:84+struct.unpack_from('>L',raw,64)[0]]
        assert raw[1024:1026]==b'BD', 'Reference mode supports raw HFS and DC42'
        v=Volume();v.read(original,preserve_desktopdb=True)
        private=args.output/(source.name+'.original.hfs')
        private.write_bytes(raw);lib.compare(private,v)
        rebuilt=args.output/(source.name+'.rebuilt.hfs')
        rebuilt.write_bytes(v.write(len(raw),desktopdb=False,bootable=True))
        copy=Volume();copy.read(rebuilt.read_bytes(),preserve_desktopdb=True)
        a={r[0]:r for r in snapshot(v)};b={r[0]:r for r in snapshot(copy)}
        assert a.keys()==b.keys()
        regenerated=[]
        for parts in a:
            if a[parts]==b[parts]: continue
            obj=v[parts]
            # Existing behavior regenerates alias type/creator and the alis
            # resource when changing CNIDs. Check all other fields, both forks'
            # companion contents, and the resolved target instead of hiding it.
            assert isinstance(obj,File) and obj.aliastarget is not None,parts
            assert a[parts][:5]==b[parts][:5] and a[parts][7:11]==b[parts][7:11],parts
            from macresources import parse_file
            def companions(f):
                return {(r.type,r.id):(r.name,bytes(r.data)) for r in parse_file(f.rsrc)
                        if (r.type,r.id)!=(b'alis',0)}
            assert companions(obj)==companions(copy[parts]),parts
            target=next((p for p,o in v.iter_paths() if o is obj.aliastarget),())
            assert copy[parts].aliastarget is copy[target],parts
            regenerated.append(':'.join(parts))
        lib.compare(rebuilt,copy)
        if args.fsck: fsck(rebuilt)
        cases.append({'source':str(source),'sha256':hashlib.sha256(original).hexdigest(),
            'entries':len(a),'regenerated_aliases':regenerated,'status':'passed'})
        print('PASS reference',source.name,len(a),'entries',len(regenerated),'aliases regenerated',flush=True)
    return cases


def regression_images(args, lib):
    from macresources import Resource,make_file
    cases=[]
    v=Volume();v['a b']=File();v['a\xa0b']=File()
    assert len(v)==1
    cases.append(('name-equivalence',v,{}))
    cases.append(('desktop',Volume(),{'desktopdb':True}))
    v=Volume();v['target']=File();v['alias']=f=File()
    f.flags=0x8000;f.aliastarget=v;f.data=b'companion'
    f.rsrc=make_file([Resource(b'TEXT',42,data=b'companion')])
    cases.append(('root-alias',v,{}))
    for length,bootable in ((15,True),(16,True),(31,True),(6,False)):
        v=Volume();v['System Folder']=Folder()
        system=File();system.type=b'ZSYS'
        system.rsrc=make_file([Resource(b'boot',1,data=b'LK'+bytes(1022))])
        finder=File();finder.type=b'FNDR'
        v['System Folder']['S'*length]=system;v['System Folder']['Finder']=finder
        cases.append(('boot-%d-%s'%(length,bootable),v,{'bootable':bootable}))
    for name,v,options in cases:
        options={'desktopdb':False,**options}
        path=args.output/(name+'.hfs')
        path.write_bytes(v.write(800*1024,**options))
        copy=Volume();copy.read(path.read_bytes(),preserve_desktopdb=True)
        lib.compare(path,copy)
        if args.fsck: fsck(path)
        print('PASS regression image',name,flush=True)
    return [name for name,_,_ in cases]


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--libhfs',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--seed',type=int,default=523912)
    p.add_argument('--cases',type=int,default=64)
    p.add_argument('--start-case',type=int,default=0,
                   help='First case index; preserves geometry when replaying a single seed')
    p.add_argument('--fsck',action='store_true')
    p.add_argument('--large',action='store_true')
    p.add_argument('--geometry',action='store_true')
    p.add_argument('--reference',type=Path,action='append',default=[],
                   help='Read a reference image; operate only on private copies')
    p.add_argument('--regressions',action='store_true')
    args=p.parse_args();args.output.mkdir(parents=True,exist_ok=True)
    lib=LibHFS(args.libhfs)
    report={'checkout':str(REPO),'seed':args.seed,'start_case':args.start_case,
            'cases':[], 'libhfs':str(args.libhfs),
            'status':'running'}
    # Compare all 256 collation weights with the independent C implementation.
    order=bytes((C.c_ubyte*256).in_dll(lib.lib,'hfs_charorder'))
    for c in range(256): assert name_key(bytes([c]).decode('mac_roman')) == order[c:c+1]
    try:
        for i in range(args.start_case,args.start_case+args.cases):
            seed=args.seed+i; v=random_volume(seed,40+i%41)
            size=[800*1024,1440*1024,4*1024*1024][i%3]
            align=[512,1024,2048,4096][i%4]
            path=args.output/('seed-%d.hfs'%seed)
            path.write_bytes(v.write(size,align=align,desktopdb=False,bootable=False))
            copy=Volume();copy.read(path.read_bytes())
            assert snapshot(copy)==snapshot(v), seed
            assert (copy.crdate,copy.mddate,copy.bkdate)==(v.crdate,v.mddate,v.bkdate)
            lib.compare(path,v)
            if args.fsck: fsck(path)
            report['cases'].append({'seed':seed,'size':size,'align':align,'status':'passed'})
            print('PASS',seed,size,align,flush=True)
        path=args.output/'independent-fragmented.hfs'
        v=independent_image(lib,path)
        normalized=args.output/'independent-normalized.hfs'
        report['hfsutils_legacy_fields_cleared']=clear_legacy_start_blocks(path,normalized)
        if args.fsck: fsck(normalized)
        valid_copy=Volume();valid_copy.read(normalized.read_bytes())
        assert snapshot(valid_copy)==snapshot(v)
        lib.compare(normalized,valid_copy)
        rebuilt=args.output/'independent-rebuilt.hfs'
        rebuilt.write_bytes(v.write(8*1024*1024,desktopdb=False,bootable=False))
        lib.compare(rebuilt,v)
        if args.fsck: fsck(rebuilt)
        report['independent_fragmented']='passed'
        print('PASS independently formatted fragmented forks',flush=True)
        if args.large:
            v=Volume();v.name='LargeCatalog'
            for i in range(20000):
                f=File();f.data=i.to_bytes(4,'big');v['%031d'%i]=f
            path=args.output/'large-catalog.hfs'
            path.write_bytes(v.write(32*1024*1024,desktopdb=False,bootable=False))
            lib.compare(path,v)
            if args.fsck: fsck(path)
            copy=Volume();copy.read(path.read_bytes());assert snapshot(copy)==snapshot(v)
            report['large_catalog']='passed (20000 files)'
            print('PASS 20000-file catalog',flush=True)
        if args.geometry:
            report['geometry']=geometry_checks(args,lib)
        if args.reference:
            report['references']=reference_checks(args,lib)
        if args.regressions:
            report['regression_images']=regression_images(args,lib)
        report['status']='passed'
    except Exception as error:
        report['status']='failed'
        report['error']=repr(error)
        raise
    finally:
        (args.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')

if __name__=='__main__': main()
