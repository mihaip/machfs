from machfs import *
from machfs import bitmanip, btree
import os
import struct
import time

def test_upperlower():
    h = Volume()
    h['alpha'] = File()
    assert h['alpha'] is h['ALPHA']
    assert list(h.keys()) == ['alpha']

def test_roundtrip():
    h = Volume()
    f = File()
    h['single file'] = f
    f.data = f.rsrc = b'1234' * 4096

    copies = [h.write(800*1024)]
    for i in range(2):
        h2 = Volume()
        h2.read(copies[-1])
        copies.append(h2.write(800*1024))

    assert copies[0] == copies[1]
    assert copies[1] == copies[2]
    assert f.data in copies[-1]


def test_open_folder():
    h = Volume()
    h.name = 'OpenFolderTest'
    h['folder'] = Folder()

    for open_folder, expected_cnid in [
        (None, 0),
        (h, 2),
        (h['folder'], 16),
    ]:
        h.open_folder = open_folder
        image = h.write(
            10 * 1024 * 1024,
            desktopdb=False,
            bootable=False,
        )

        mdb = struct.unpack_from(
            '>2sLLHHHHHLLHLH28pLHLLLHLL32sHHHL12sL12s', image, 1024
        )
        assert struct.unpack('>8L', mdb[22])[2] == expected_cnid

        copy = Volume()
        copy.read(image)
        if open_folder is None:
            assert copy.open_folder is None
        elif open_folder is h:
            assert copy.open_folder is copy
        else:
            assert copy.open_folder is copy['folder']

    h['folder']['app'] = File()
    h.open_folder = None
    image = h.write(
        10 * 1024 * 1024,
        desktopdb=False,
        bootable=False,
        startapp=('folder', 'app'),
    )
    mdb = struct.unpack_from(
        '>2sLLHHHHHLLHLH28pLHLLLHLL32sHHHL12sL12s', image, 1024
    )
    finder_info = struct.unpack('>8L', mdb[22])
    assert finder_info[1] == 16
    assert finder_info[2] == 0


def test_file_catalog_reserved_fields():
    h = Volume()
    h.name = 'CatalogFieldsTest'
    f = File()
    f.data = b'data fork'
    f.rsrc = b'resource fork'
    h['file'] = f

    image = h.write(
        10 * 1024 * 1024,
        desktopdb=False,
        bootable=False,
    )

    mdb = struct.unpack_from(
        '>2sLLHHHHHLLHLH28pLHLLLHLL32sHHHL12sL12s', image, 1024
    )
    allocation_block_size = mdb[8]
    allocation_block_start = mdb[10]
    catalog_size = mdb[-2]
    catalog_extents = btree.unpack_extent_record(mdb[-1])
    catalog = b''.join(
        image[
            512 * allocation_block_start + first_block * allocation_block_size:
            512 * allocation_block_start + (first_block + block_count) * allocation_block_size
        ]
        for first_block, block_count in catalog_extents
    )[:catalog_size]

    file_record = None
    for record in btree.dump_btree(catalog):
        key_length = record[0]
        value = record[bitmanip.pad_up(1 + key_length, 2):]
        if value[0] == 2:
            file_record = struct.unpack(
                '>BxBB16sLHLLHLLLLL16sH12s12sL', value
            )
            break

    assert file_record is not None
    assert file_record[1] & 0x02 == 0  # kHFSThreadExistsMask
    assert file_record[5] == 0  # dataStartBlock (reserved)
    assert file_record[8] == 0  # rsrcStartBlock (reserved)
    assert file_record[18] == 0  # reserved
    assert btree.unpack_extent_record(file_record[16])
    assert btree.unpack_extent_record(file_record[17])


def test_map_nodes():
    # Force enough leaf nodes to require more bitmap space than the header
    # node provides, and enough total nodes to require multiple map nodes.
    records = [(i.to_bytes(4, 'big'), bytes(470)) for i in range(6000)]
    tree = btree.make_btree(records, bthKeyLen=37, blksize=512)

    first_map_node, _, _, _, header_records = btree._unpack_btree_node(tree, 0)
    assert first_map_node != 0
    total_nodes, free_nodes = struct.unpack_from('>LL', header_records[0], 22)
    bitmap = header_records[2]

    map_node_count = 0
    map_node = first_map_node
    while map_node:
        # The BeOS R3 HFS driver rejects a free-space offset other than 506.
        assert struct.unpack_from('>HH', tree, 512 * map_node + 508) == (506, 14)
        assert tree[512 * map_node + 506:512 * map_node + 508] == bytes(2)
        map_node, _, node_type, node_height, records = btree._unpack_btree_node(
            tree, 512 * map_node
        )
        assert node_type == 2
        assert node_height == 0
        assert len(records) == 1
        assert len(records[0]) == 492
        bitmap += records[0]
        map_node_count += 1

    assert map_node_count > 1
    bits = [bool(byte & (0x80 >> bit)) for byte in bitmap for bit in range(8)]
    assert len(bits) >= total_nodes
    assert all(bits[:total_nodes - free_nodes])
    assert not any(bits[total_nodes - free_nodes:])


def test_macos_mount():
    h = Volume()
    h.name = 'ElmoTest'
    hf = File()
    hf.data = b'12345' * 10
    for i in reversed(range(100)):
        last = 'testfile-%03d' % i
        h[last] = hf
    ser = h.write(10*1024*1024)

    open('/tmp/SMALL.dmg','wb').write(ser)
    os.system('hdiutil attach /tmp/SMALL.dmg')
    n = 10
    while 1:
        n += 1
        assert n < 200
        time.sleep(0.1)
        try:
            os.stat('/Volumes/ElmoTest/testfile-000')
        except:
            pass
        else:
            break
    recovered = open('/Volumes/ElmoTest/' + last,'rb').read()
    os.system('umount /Volumes/ElmoTest')
    assert recovered == hf.data

    h2 = Volume()
    h2.read(ser)
    assert h2['testfile-000'].data == hf.data

# def test_extents_overflow():
#     h = Volume()
#     h.read(open('SourceForEmulator.dmg','rb').read())
#     assert h['aa'].data == b'a' * 278528

def test_many_sizes():
    sizes = [800*1024, 1024*1024]
    while sizes[-1] < 4*1024*1024*1024:
        sizes.append(sizes[-1] * 2)

    # okay, we have heaps of sizes
    v = Volume()
    v.name = 'ImportantTestVol'
    for s in sizes:
        ser = v.write(s-512)
        open('/tmp/SMALL-%X.dmg'%s, 'wb').write(ser)
