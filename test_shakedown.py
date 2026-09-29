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
            if count:
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


if __name__ == '__main__':
    unittest.main()
