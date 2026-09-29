"""Focused regressions; run with python3 -m unittest -v test_shakedown."""
import random
import struct
import unittest

from machfs import Volume, Folder, File, btree
from machfs.main import _catalog_rec_sort, OutOfSpaceError
from machfs.main import _suggest_allocblk_size, _get_every_extent



def image(volume):
    return volume.write(800 * 1024, desktopdb=False, bootable=False)


def catalog_records(data):
    blocksize = struct.unpack_from('>L', data, 1024 + 20)[0]
    start = struct.unpack_from('>H', data, 1024 + 28)[0] * 512
    size = struct.unpack_from('>L', data, 1024 + 146)[0]
    extents = btree.unpack_extent_record(data[1024 + 150:1024 + 162])
    tree = b''.join(data[start+a*blocksize:start+(a+b)*blocksize] for a,b in extents)[:size]
    return list(btree.dump_btree(tree))


class ShakedownTests(unittest.TestCase):
    def test_allocation_block_boundary(self):
        self.assertEqual(_suggest_allocblk_size(32*1024*1024-512,512),512)
        self.assertEqual(_suggest_allocblk_size(32*1024*1024,512),1024)
        for align in (512,1024,2048,4096):
            for size in (400*1024,32*1024*1024,2**32-512,2**32):
                block = _suggest_allocblk_size(size,align)
                self.assertEqual(block % align,0)
                self.assertLessEqual(size//block,65535)

    def test_diskcopy_header_lengths(self):
        for size,tags,kind,fmt in ((400*1024,0,0,2),(400*1024,9600,0,2),
                (800*1024,0,1,0x22),(800*1024,19200,1,0x22),
                (1440*1024,0,3,2)):
            v=Volume();v['file']=File();v['file'].data=b'wrapped'
            raw=v.write(size,desktopdb=False)
            # Disk Copy checksum: add each big-endian word, rotate right one.
            checksum=0
            for word, in struct.iter_unpack('>H',raw):
                checksum=(checksum+word)&0xffffffff
                checksum=(checksum>>1)|((checksum&1)<<31)
            header=struct.pack('>64pLLLLBBH',b'Test',size,tags,checksum,0,kind,fmt,256)
            wrapped=header+raw+bytes(tags)
            copy=Volume();copy.read(wrapped)
            self.assertEqual(copy['file'].data,b'wrapped')
            with self.assertRaises(ValueError): Volume().read(wrapped[:-1])

    def test_no_progress_in_extent_chain(self):
        initial=struct.pack('>6H',1,1,0,0,0,0)
        with self.assertRaises(ValueError):
            _get_every_extent(2,initial,16,{(16,'data',1):bytes(12)},'data')
        with self.assertRaises(ValueError):
            _get_every_extent(2,initial,16,{},'data')

    def test_hfs_name_equivalence(self):
        v = Volume()
        v['a b'] = File()
        self.assertIs(v['a b'], v['a\xa0b'])
        replacement = File()
        v['a\xa0b'] = replacement
        self.assertEqual(len(v), 1)
        self.assertIs(v['a b'], replacement)
        del v[b'a b']
        self.assertFalse(v)

    def test_all_macroman_name_pairs(self):
        # Use the writer's existing HFS collation as a separate oracle for
        # mapping equality, including Unicode case pairs HFS keeps distinct.
        names = [bytes([c]).decode('mac_roman') for c in range(1, 256) if c != 58]
        def sortkey(name):
            return _catalog_rec_sort((b'\0\0\0\2\1' + name.encode('mac_roman'),))
        for name in names:
            folder = Folder(); obj = File(); folder[name] = obj
            for other in names:
                self.assertEqual(other in folder, sortkey(name) == sortkey(other), (name, other))

    def test_empty_btree(self):
        tree = btree.make_btree([], bthKeyLen=7, blksize=512)
        self.assertEqual(list(btree.dump_btree(tree)), [])

    def test_locked_and_backup_date(self):
        v = Volume(); v.bkdate = 1234567
        v['locked'] = f = File(); f.locked = True
        result = image(v)
        file_record = next(r for r in catalog_records(result) if r[(r[0]+2)&~1] == 2)
        self.assertEqual(file_record[((file_record[0]+2)&~1)+2] & 1, 1)
        copy = Volume(); copy.read(result)
        self.assertTrue(copy['locked'].locked)
        self.assertEqual(copy.bkdate, v.bkdate)

    def test_write_does_not_mutate_desktop_entries(self):
        v = Volume(); v['Desktop'] = f = File(); f.data = b'original'
        before = list(v.items())
        v.write()
        self.assertEqual(list(v.items()), before)
        self.assertIs(v['Desktop'], f)
        self.assertEqual(v['Desktop'].data, b'original')

    def test_failed_write_does_not_mutate_volume(self):
        v = Volume(); v['huge'] = f = File(); f.data = bytes(900*1024)
        before = list(v.items())
        with self.assertRaises(OutOfSpaceError):
            v.write()
        self.assertEqual(list(v.items()), before)
        self.assertEqual(len(v), 1)

    def test_invalid_leaf_offsets(self):
        tree = bytearray(btree.make_btree([(b'key', b'value')], 37, 512))
        struct.pack_into('>H', tree, 512+510, 12)
        with self.assertRaises(ValueError):
            list(btree.dump_btree(tree))

    def test_volume_geometry_rejected(self):
        result = bytearray(image(Volume()))
        struct.pack_into('>L', result, 1024+20, 0)
        with self.assertRaises(ValueError):
            Volume().read(result)

    def test_truncated_forks_and_out_of_range_extents(self):
        v=Volume();v['file']=File();v['file'].data=b'payload'
        raw=image(v)
        with self.assertRaises(ValueError): Volume().read(raw[:4096])
        record=next(r for r in catalog_records(raw) if r[(r[0]+2)&~1]==2)
        offset=raw.index(record)+((record[0]+2)&~1)
        data=bytearray(raw)
        count=struct.unpack_from('>H',raw,1042)[0]
        struct.pack_into('>H',data,offset+74,count)
        with self.assertRaises(ValueError): Volume().read(data)

    def test_byte_volume_name(self):
        v=Volume();v.name=b'Bytes'
        copy=Volume();copy.read(image(v))
        self.assertEqual(copy.name,'Bytes')


def validate_tree(tree):
    """Independent structural oracle: never calls machfs's node reader."""
    def node(number):
        data=tree[number*512:(number+1)*512]
        assert len(data)==512
        forward,backward,kind,height,count=struct.unpack_from('>LLBBH',data)
        offsets=[struct.unpack_from('>H',data,510-2*i)[0] for i in range(count+1)]
        assert offsets[0]==14
        assert offsets[-1]<=510-2*count
        assert all(x%2==0 for x in offsets)
        assert all(a<b for a,b in zip(offsets,offsets[1:]))
        return forward,backward,kind,height,[data[a:b] for a,b in zip(offsets,offsets[1:])]
    forward,_,kind,height,records=node(0)
    assert kind==1 and height==0
    depth,root,nrecs,first,last,size,keylen,total,free=struct.unpack_from('>HLLLLHHLL',records[0])
    assert size==512 and total*512==len(tree)
    bitmap=records[2];maps=set();previous=0
    while forward:
        assert forward not in maps
        maps.add(forward)
        nextnode,back,kind,height,records=node(forward)
        assert (back,kind,height)==(previous,2,0)
        assert len(records)==1 and len(records[0])==492
        bitmap+=records[0];previous=forward;forward=nextnode
    reached={0}|maps
    levels={};leaves=[];record_count=0
    def visit(number,height):
        nonlocal record_count
        assert number not in reached
        reached.add(number)
        forward,back,kind,actual_height,records=node(number)
        assert actual_height==height and records
        levels.setdefault(height,[]).append((number,forward,back))
        if height==1:
            assert kind==255
            leaves.append(number);record_count+=len(records)
        else:
            assert kind==0
            for rec in records:
                assert rec[0]==keylen
                pointer=struct.unpack_from('>L',rec,keylen+1)[0]
                child_first=visit(pointer,height-1)
                assert rec[1:1+child_first[0]]==child_first[1:1+child_first[0]]
        return records[0]
    if root: visit(root,depth)
    assert record_count==nrecs
    assert (leaves[0],leaves[-1])==(first,last) if leaves else first==last==depth==0
    for level in levels.values():
        for i,(number,forward,back) in enumerate(level):
            assert back==(level[i-1][0] if i else 0)
            assert forward==(level[i+1][0] if i+1<len(level) else 0)
    allocated={i for i in range(len(bitmap)*8) if bitmap[i//8]&(128>>(i%8))}
    assert len(bitmap)*8>=total
    assert allocated==reached
    assert len(reached)==total-free
    assert all(tree[n*512:(n+1)*512]==bytes(512) for n in range(total) if n not in reached)
    return total,len(maps)


class StructureTests(unittest.TestCase):
    def test_seeded_trees(self):
        rng=random.Random(523912)
        for count in [0,1,8,9,64,65,512]+[rng.randrange(2,600) for _ in range(40)]:
            records=[(i.to_bytes(4,'big'),rng.randbytes(rng.randrange(1,460))) for i in range(count)]
            tree=btree.make_btree(records,37,rng.choice([512,1024,2048,4096]))
            validate_tree(tree)
            self.assertEqual(len(list(btree.dump_btree(tree))),count)

    def test_map_boundaries(self):
        def node_count(leaves):
            count=leaves+1
            while leaves>1:
                leaves=(leaves+7)//8;count+=leaves
            return count
        cases=set()
        for threshold in (2048,5984,9920):
            first=next(n for n in range(1,10000) if node_count(n)>=threshold)
            cases.update(range(first-2,first+3))
        for count in sorted(cases):
            for block in (512,4096,32768):
                tree=btree.make_btree([(i.to_bytes(4,'big'),bytes(470)) for i in range(count)],37,block)
                validate_tree(tree)

    def test_seeded_bad_offsets(self):
        rng=random.Random(5984)
        original=btree.make_btree([(b'key',b'value')],37,512)
        for offset in [0,12,15,509,510,512,65535]+[rng.randrange(513,65536) for _ in range(50)]:
            tree=bytearray(original)
            struct.pack_into('>H',tree,1022,offset)
            with self.assertRaises(ValueError): list(btree.dump_btree(tree))

    def test_leaf_cycles_and_descriptor_mutations(self):
        original=btree.make_btree([(bytes([i]),bytes(470)) for i in range(4)],37,512)
        for offset,fmt,value in ((512,'>L',1),(512+4,'>L',1),(512+8,'>B',0),
                (512+9,'>B',0),(512+10,'>H',65535),(14+6,'>L',1)):
            tree=bytearray(original);struct.pack_into(fmt,tree,offset,value)
            with self.assertRaises(ValueError): list(btree.dump_btree(tree))

    def test_sparse_geometry(self):
        for align in (512,2048,4096):
            for size in (400*1024,800*1024,2**25-512,2**25,2**25+512,
                         2**26-512,2**26,2**31-512,2**31,2**32-512,2**32):
                left,hole,right=Volume().write(size,align=align,desktopdb=False,sparse=True)
                self.assertEqual(len(left)+hole+len(right),size)
                self.assertGreaterEqual(hole,0)
                count,block=struct.unpack_from('>HL',left,1042)
                start=struct.unpack_from('>H',left,1052)[0]*512
                self.assertEqual(block%align,0);self.assertEqual(start%align,0)
                self.assertLessEqual(start+count*block,size-1024)
                self.assertLessEqual(size//block,65535)
                self.assertEqual(left[1024:1536],right[:512])


class BootAndAliasTests(unittest.TestCase):
    def test_alias_targets_and_cycles(self):
        v=Volume();v['folder']=Folder();v['folder']['file']=File()
        for name,target in [('root',v),('folder alias',v['folder']),('file alias',v['folder','file'])]:
            f=File();f.flags=0x8000;f.aliastarget=target;v[name]=f
        for _ in range(2):
            copy=Volume();copy.read(image(v));v=copy
            self.assertIs(v['root'].aliastarget,v)
            self.assertIs(v['folder alias'].aliastarget,v['folder'])
            self.assertIs(v['file alias'].aliastarget,v['folder','file'])
        v['root'].aliastarget=File()
        with self.assertRaises(ValueError): image(v)
        v['root'].aliastarget=v['root']
        with self.assertRaises(ValueError): image(v)


if __name__ == '__main__':
    unittest.main()
