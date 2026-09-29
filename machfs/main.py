import enum
import struct
from macresources import Resource, make_file, parse_file
from . import btree, bitmanip
from ._names import _HFS_CHAR_ORDER
from .directory import AbstractFolder, Folder, File

class FinderFlags(enum.IntEnum):
    kIsOnDesk = 0x0001
    kColor = 0x000e
    kIsShared = 0x0040
    kHasBeenInited = 0x0100
    kHasCustomIcon = 0x0400
    kIsStationery = 0x0800
    kNameLocked = 0x1000
    kHasBundle = 0x2000
    kIsInvisible = 0x4000
    kIsAlias = 0x8000



def _catalog_rec_sort(b):
    b = b[0] # we are only sorting keys!

    return b[:4] + b[5:].translate(_HFS_CHAR_ORDER)


def _suggest_allocblk_size(volsize, minalign):
    # Apple validates the block size against the entire volume, including
    # metadata, rather than just the eventual allocation area. In particular,
    # a 32 MiB volume needs 1024-byte blocks even though its allocation area
    # would fit in 65535 blocks of 512 bytes.
    retval = minalign
    while volsize // retval > 65535:
        retval += minalign
    return retval


def _get_every_extent(nblocks, firstrecord, cnid, xoflow, fork):
    accum = 0
    extlist = []

    for a, b in btree.unpack_extent_record(firstrecord):
        if not b: continue
        accum += b
        extlist.append((a, b))

    while accum < nblocks:
        try:
            nextrecord = xoflow[cnid, fork, accum]
        except KeyError:
            raise ValueError('Missing extents overflow record') from None
        extents = btree.unpack_extent_record(nextrecord)
        if not extents:
            raise ValueError('Empty extents overflow record')
        for a, b in extents:
            accum += b
            extlist.append((a, b))

    return extlist


def _encode_name(name, kind='file'):
    longest = {'file': 31, 'vol': 27, 'bb': 15}[kind]

    try:
        encoded = name.encode('mac_roman')
    except UnicodeEncodeError:
        raise BadNameError(name)
    except AttributeError:
        encoded = bytes(name)

    if not 1 <= len(encoded) <= longest or b':' in encoded:
        raise BadNameError(name)

    return encoded


def _bb_name(name):
    return bitmanip.pstring(_encode_name(name)).ljust(16)


def _common_prefix(*tuples):
    for i in range(min(len(t) for t in tuples)):
        for t in tuples[1:]:
            if t[i] != tuples[0][i]:
                return i

    return min(len(t) for t in tuples)


def _link_aliases(vol_cr_date, cnid_dict): # vol creation date confirms within-volume alias
    for cnid, obj in cnid_dict.items():
        try:
            if obj.flags & FinderFlags.kIsAlias:
                alis_rsrc = next(r.data for r in parse_file(obj.rsrc) if r.type == b'alis')

                # print(hex(obj.flags))
                # print(obj)
                # open('/tmp/interpreting' + hex(cnid),'wb').write(alis_rsrc)

                userType, aliasSize, aliasVersion, \
                thisAliasKind, volumeName, volumeCrDate, \
                volumeSig, volumeType, parDirID, fileName, \
                fileNum, fileCrDate, fileType, fdCreator, \
                nlvlFrom, nlvlTo, volumeAttributes, volumeFSID \
                = struct.unpack_from('>4s H hh 28p L 2s hL 64p LL 4s4s HHLh', alis_rsrc)

                # print(userType, aliasSize, aliasVersion,
                #     thisAliasKind, volumeName, volumeCrDate,
                #     volumeSig, volumeType, parDirID, fileName,
                #     fileNum, fileCrDate, fileType, fdCreator,
                #     nlvlFrom, nlvlTo, volumeAttributes, volumeFSID)

                if volumeCrDate != vol_cr_date: raise ValueError

                obj.aliastarget = cnid_dict[fileNum]

        except (AttributeError, KeyError, StopIteration, ValueError, struct.error):
            pass


def _defer_special_files(iter_paths, root=None):
    """Defer special files (aliases) to late CNIDs, and resolve aliases"""
    approved_dict = {id(root): ()} if root is not None else {}
    unapproved = []

    for path, obj in iter_paths:
        if isinstance(obj, File) and obj.aliastarget is not None:
            unapproved.append((path, obj))
        else:
            yield path, obj, None
            approved_dict[id(obj)] = path

    while unapproved:
        made_progress = False

        for i in reversed(range(len(unapproved))):
            path, obj = unapproved[i]

            try:
                targetpath = approved_dict[id(obj.aliastarget)]
            except KeyError:
                continue

            yield path, obj, targetpath
            approved_dict[id(obj)] = path

            unapproved.pop(i)
            made_progress = True

        if not made_progress:
            raise ValueError('Alias target is outside this volume or aliases form a cycle')


def _alis_append(alis, kind, data):
    if len(alis) % 2: alis.append(0)
    alis.extend(struct.pack('>hH', kind, len(data)))
    alis.extend(data)
    if len(alis) % 2: alis.append(0)


class _TempWrapper:
    """Volume uses this to store metadata while serialising"""
    def __init__(self, of):
        self.of = of


class OutOfSpaceError(Exception):
    pass


class BadNameError(Exception):
    pass


class Volume(AbstractFolder):
    def __init__(self):
        super().__init__()

        self.crdate = self.mddate = self.bkdate = 0
        self.name = 'Untitled'
        self.usrInfo = None
        self.fndrInfo = None
        self.open_folder = None

    def read(self, from_volume, preserve_desktopdb=False):
        valid_volume = False
        if (len(from_volume) >= 84 and from_volume[0] <= 63
                and from_volume[82:84] == b'\x01\x00'
                and from_volume[1108:1110] == b'BD'):
            # Disk Copy 4.2: the header declares data and tag lengths. Do not
            # guess the wrapper from a short list of floppy image sizes.
            data_size, tag_size = struct.unpack_from('>LL', from_volume, 64)
            if data_size < 1536 or data_size % 512 or 84 + data_size + tag_size != len(from_volume):
                raise ValueError('Invalid Disk Copy 4.2 image lengths')
            from_volume = from_volume[84:84+data_size]
            valid_volume = True
        else:
            # 0..511 byte header
            for i in range(0, len(from_volume), 512):
                if from_volume[i+1024:i+1024+2] == b'BD':
                    if i: from_volume = from_volume[i:]
                    valid_volume = True
                    break

        if not valid_volume:
            raise ValueError('Magic number not found in %d byte image' % (len(from_volume)))
        if len(from_volume) < 1536:
            raise ValueError('Truncated HFS volume header')

        drSigWord, drCrDate, drLsMod, drAtrb, drNmFls, \
        drVBMSt, drAllocPtr, drNmAlBlks, drAlBlkSiz, drClpSiz, drAlBlSt, \
        drNxtCNID, drFreeBks, drVN, drVolBkUp, drVSeqNum, \
        drWrCnt, drXTClpSiz, drCTClpSiz, drNmRtDirs, drFilCnt, drDirCnt, \
        drFndrInfo, drVCSize, drVBMCSize, drCtlCSize, \
        drXTFlSize, drXTExtRec, \
        drCTFlSize, drCTExtRec, \
        = struct.unpack_from('>2sLLHHHHHLLHLH28pLHLLLHLL32sHHHL12sL12s', from_volume, 1024)

        if (drSigWord != b'BD' or drAlBlkSiz < 512 or drAlBlkSiz % 512
                or not drNmAlBlks or drAlBlSt < 3
                or 512*drAlBlSt + drAlBlkSiz*drNmAlBlks > len(from_volume)):
            raise ValueError('Invalid HFS allocation geometry')

        self.crdate, self.mddate, self.bkdate = drCrDate, drLsMod, drVolBkUp

        block2offset = lambda block: 512*drAlBlSt + drAlBlkSiz*block
        def getfork(size, extrec1, cnid, fork):
            if size > drNmAlBlks * drAlBlkSiz:
                raise ValueError('Fork larger than allocation area')
            extents = _get_every_extent((size+drAlBlkSiz-1)//drAlBlkSiz,
                                       extrec1, cnid, extoflow, fork)
            if any(first + count > drNmAlBlks for first, count in extents):
                raise ValueError('Extent outside allocation area')
            return b''.join(from_volume[block2offset(first):block2offset(first+count)]
                            for first, count in extents)[:size]

        extoflow = {}
        for rec in btree.dump_btree(getfork(drXTFlSize, drXTExtRec, 3, 'data')):
            if rec[0] != 7: continue
            xkrFkType, xkrFNum, xkrFABN, extrec = struct.unpack_from('>xBLH12s', rec)
            if xkrFkType == 0xFF:
                fork = 'rsrc'
            elif xkrFkType == 0:
                fork = 'data'
            extoflow[xkrFNum, fork, xkrFABN] = extrec

        cnids = {}
        childlist = [] # list of (parent_cnid, child_name, child_object) tuples

        prev_key = None
        for rec in btree.dump_btree(getfork(drCTFlSize, drCTExtRec, 4, 'data')):
            # create a directory tree from the catalog file
            rec_len = rec[0]
            if rec_len == 0: continue

            key = rec[2:1+rec_len]
            val = rec[bitmanip.pad_up(1+rec_len, 2):]

            # if prev_key: # Uncomment this to test the sort order with 20% performance cost!
            #     if _catalog_rec_sort((prev_key,)) >= _catalog_rec_sort((key,)):
            #         raise ValueError('Sort error: %r, %r' % (prev_key, key))
            # prev_key = key

            ckrParID, namelen = struct.unpack_from('>LB', key)
            ckrCName = key[5:5+namelen]

            datatype = (None, 'dir', 'file', 'dthread', 'fthread')[val[0]]
            datarec = val[2:]

            # print(datatype + '\t' + repr(key))
            # print('\t', datarec)
            # print()

            if datatype == 'dir':
                dirFlags, dirVal, dirDirID, dirCrDat, dirMdDat, dirBkDat, dirUsrInfo, dirFndrInfo \
                = struct.unpack_from('>HHLLLL16s16s', datarec)

                f = Folder()
                cnids[dirDirID] = f
                childlist.append((ckrParID, ckrCName, f))

                f.flags, f.usrInfo, f.fndrInfo, f.crdate, f.mddate, f.bkdate = \
                    dirFlags, dirUsrInfo, dirFndrInfo, dirCrDat, dirMdDat, dirBkDat

            elif datatype == 'file':
                filFlags, filTyp, filUsrWds, filFlNum, \
                filStBlk, filLgLen, filPyLen, \
                filRStBlk, filRLgLen, filRPyLen, \
                filCrDat, filMdDat, filBkDat, \
                filFndrInfo, filClpSize, \
                filExtRec, filRExtRec, \
                = struct.unpack_from('>BB16sLHLLHLLLLL16sH12s12sxxxx', datarec)

                f = File()
                cnids[filFlNum] = f
                childlist.append((ckrParID, ckrCName, f))

                f.crdate, f.mddate, f.bkdate = filCrDat, filMdDat, filBkDat
                f.type, f.creator, f.flags, f.y, f.x = struct.unpack_from('>4s4sHhh', filUsrWds)
                f.fndrInfo = filFndrInfo
                f.locked = bool(filFlags & 1)

                f.data = getfork(filLgLen, filExtRec, filFlNum, 'data')
                f.rsrc = getfork(filRLgLen, filRExtRec, filFlNum, 'rsrc')

            # elif datatype == 'dthread':
            #     print('dir thread:', rec)
            # elif datatype == 'fthread':
            #     print('fil thread:', rec)

        for parent_cnid, child_name, child_obj in childlist:
            if parent_cnid != 1:
                parent_obj = cnids[parent_cnid]
                parent_obj[child_name] = child_obj
            else:
                # This should be dir ID 2 with parent 1, which is information
                # about the root folder in the volume, copy it up there.
                self.name = child_name.decode('mac_roman')
                self.flags = child_obj.flags
                self.usrInfo = child_obj.usrInfo
                self.fndrInfo = child_obj.fndrInfo

        self.update(cnids[2])

        open_folder_cnid = struct.unpack_from('>L', drFndrInfo, 8)[0]
        if open_folder_cnid == 2:
            self.open_folder = self
        else:
            open_folder = cnids.get(open_folder_cnid)
            self.open_folder = open_folder if isinstance(open_folder, AbstractFolder) else None

        if not preserve_desktopdb:
            self.pop('Desktop', None)
            self.pop('Desktop DB', None)
            self.pop('Desktop DF', None)

        cnids[2] = self
        _link_aliases(drCrDate, cnids)

    def write(self, size=800*1024, align=512, desktopdb=True, bootable=True, startapp=None, sparse=False):
        if align < 512 or align % 512:
            raise ValueError('align must be multiple of 512')

        if size < 400 * 1024 or size % 512:
            raise ValueError('size must be a multiple of 512b and >= 400K')

        # These are declared up here because they are needed for aliases
        drVN = _encode_name(self.name, 'vol')
        drSigWord = b'BD'
        drAtrb = 1<<8                  # volume attributes (hwlock, swlock, CLEANUNMOUNT, badblocks)
        drCrDate, drLsMod, drVolBkUp = self.crdate, self.mddate, self.bkdate

        # overall layout:
        #   1. two boot blocks (offset=0)
        #   2. one volume control block (offset=2)
        #   3. some bitmap blocks (offset=3)
        #   4. many allocation blocks
        #   5. duplicate VCB (offset=-2)
        #   6. unused block (offset=-1)

        # so we will our best guess at these variables as we go:
        # drNmAlBlks, drAlBlkSiz, drAlBlSt

        # the smallest possible alloc block size
        drAlBlkSiz = _suggest_allocblk_size(size, align)

        # how many blocks will we use for the bitmap?
        # (cheat by adding blocks to align the alloc area)
        bitmap_blk_cnt = 0
        while (size - (5+bitmap_blk_cnt)*512) // drAlBlkSiz > bitmap_blk_cnt*512*8:
            bitmap_blk_cnt += 1
        while (3+bitmap_blk_cnt)*512 % align:
            bitmap_blk_cnt += 1

        # decide how many alloc blocks there will be
        drNmAlBlks = (size - (5+bitmap_blk_cnt)*512) // drAlBlkSiz
        blkaccum = []

        def accumulate(x):
            blkaccum.extend(x)
            if len(blkaccum) > drNmAlBlks:
                raise OutOfSpaceError

        # <<< put the empty extents overflow file in here >>>
        extoflowfile = btree.make_btree([], bthKeyLen=7, blksize=drAlBlkSiz)
        # also need to do some cleverness to ensure that this gets picked up...
        drXTFlSize = len(extoflowfile)
        drXTExtRec_Start = len(blkaccum)
        accumulate(bitmanip.chunkify(extoflowfile, drAlBlkSiz))
        drXTExtRec_Cnt = len(blkaccum) - drXTExtRec_Start

        # write all the files in the volume
        topwrap = _TempWrapper(self)
        topwrap.path = (self.name,)
        topwrap.cnid = 2

        godwrap = _TempWrapper(None)
        godwrap.cnid = 1

        # Generate Desktop files in a private root mapping, including on failure.
        contents = AbstractFolder(self.items())
        if desktopdb:
            f = File()
            f.type, f.creator = b'FNDR', b'ERIK'
            f.flags = FinderFlags.kIsInvisible
            f.rsrc = make_file([Resource(b'STR ', 0, data=b'\x0AFinder 1.0')])
            contents['Desktop'] = f
            if size >= 2*1024*1024:
                f = File()
                f.type, f.creator = b'BTFL', b'DMGR'
                f.flags = FinderFlags.kIsInvisible
                f.data = btree.make_btree([], bthKeyLen=37, blksize=drAlBlkSiz)
                contents['Desktop DB'] = f
                f = File()
                f.type, f.creator = b'DTFL', b'DMGR'
                f.flags = FinderFlags.kIsInvisible
                contents['Desktop DF'] = f

        system_folder_cnid = 0
        startapp_folder_cnid = 0
        bootblocks = bytearray(1024)

        path2wrap = {(): godwrap, (self.name,): topwrap}
        drNxtCNID = 16
        for path, obj, aliastarget in _defer_special_files(contents.iter_paths(), self):
            path = (self.name,) + path
            wrap = _TempWrapper(obj)
            path2wrap[path] = wrap
            wrap.path = path
            wrap.cnid = drNxtCNID; drNxtCNID += 1

            if isinstance(obj, File) and obj.type.upper() == b'ZSYS':
                try:
                    sysname = path[-1]

                    fellows = path2wrap[path[:-1]].of.items()
                    fndrname = next(n for (n, o) in fellows if isinstance(o, File) and o.type == b'FNDR')

                    sysresources = parse_file(obj.rsrc)
                    boot1 = next(r for r in sysresources if (r.type, r.id) == (b'boot', 1))
                    bb = bytearray(boot1.data)
                    if len(bb) != 1024: raise ValueError

                    bb[0x0A:0x1A] = _bb_name(sysname)
                    bb[0x1A:0x2A] = _bb_name(fndrname)

                except:
                    pass

                else:
                    bootblocks[:] = bb
                    system_folder_cnid = path2wrap[path[:-1]].cnid

            if isinstance(obj, File) and startapp and path[1:] == tuple(startapp):
                startapp_folder_cnid = path2wrap[path[:-1]].cnid

            if isinstance(obj, File):
                wrap.data, wrap.rsrc = obj.data, obj.rsrc
                wrap.type, wrap.creator = obj.type, obj.creator

            # This is the place to manage your special files (aliases for now)
            if aliastarget is not None:
                aliastarget = (self.name,) + aliastarget # match the convention for this function
                targetobj = path2wrap[aliastarget].of # probe the target to set some metadata

                if isinstance(targetobj, Folder):
                    wrap.creator = b'MACS'
                    wrap.type = b'fdrp'

                elif isinstance(targetobj, Volume):
                    wrap.creator = b'MACS'
                    wrap.type = b'hdsk' if size > 1440*1024 else b'flpy'

                elif isinstance(targetobj, File):
                    wrap.creator = targetobj.creator

                    if targetobj.type == b'APPL':
                        wrap.type = b'adrp'
                    else:
                        wrap.type = targetobj.type

                userType = b''
                aliasSize = 9999 # fill this short at offset 4
                aliasVersion = 2
                thisAliasKind = 1 if isinstance(targetobj, AbstractFolder) else 0
                volumeName = drVN
                volumeCrDate = drCrDate
                volumeSig = drSigWord
                volumeType = 5 #2 if size == 400*1024 else 3 if size == 800*1024 else 4 if size == 1440*1024 else 1
                parDirID = path2wrap[aliastarget[:-1]].cnid
                fileName = _encode_name(aliastarget[-1])
                fileNum = path2wrap[aliastarget].cnid
                fileCrDate = path2wrap[aliastarget].of.crdate
                fileType = targetobj.type if isinstance(targetobj, File) else b''
                fdCreator = targetobj.creator if isinstance(targetobj, File) else b''
                nlvlFrom = len(path) - _common_prefix(path, aliastarget)
                nlvlTo = len(aliastarget) - _common_prefix(path, aliastarget)
                volumeAttributes = 0 # this is aliasmgr-specific
                volumeFSID = 0

                # Stress test: find file by name, not CNID
                # fileNum = 0

                alis = Resource(b'alis', 0, name=path[-1])
                alis.data[:] = struct.pack('>4s H hh 28p L 2s hL 64p LL 4s4s HHLh',
                    userType, aliasSize, aliasVersion, \
                    thisAliasKind, volumeName, volumeCrDate, \
                    volumeSig, volumeType, parDirID, fileName, \
                    fileNum, fileCrDate, fileType, fdCreator, \
                    nlvlFrom, nlvlTo, volumeAttributes, volumeFSID \
                ) + bytes(10) # reserved stuff

                if len(aliastarget) > 1:
                    _alis_append(alis.data, 0, aliastarget[-2].encode('mac_roman'))
                _alis_append(alis.data, 2, ':'.join(aliastarget).encode('mac_roman'))
                _alis_append(alis.data, -1, b'')

                struct.pack_into('>H', alis.data, 4, len(alis.data))

                # open('/tmp/creating','wb').write(alis.data)

                # Regenerate the target record without discarding companion
                # resources (icons, custom metadata) or the original data fork.
                resources = [r for r in parse_file(obj.rsrc)
                             if (r.type, r.id) != (b'alis', 0)]
                wrap.rsrc = make_file([*resources, alis])

            if isinstance(obj, File):
                wrap.dfrk = wrap.rfrk = (0, 0)
                if wrap.data:
                    pre = len(blkaccum)
                    accumulate(bitmanip.chunkify(wrap.data, drAlBlkSiz))
                    wrap.dfrk = (pre, len(blkaccum)-pre)
                if wrap.rsrc:
                    pre = len(blkaccum)
                    accumulate(bitmanip.chunkify(wrap.rsrc, drAlBlkSiz))
                    wrap.rfrk = (pre, len(blkaccum)-pre)

        catalog = [] # (key, value) tuples

        drFilCnt = 0
        drDirCnt = -1 # to exclude the root directory

        for path, wrap in path2wrap.items():
            if wrap.cnid == 1: continue

            obj = wrap.of
            pstrname = bitmanip.pstring(_encode_name(path[-1], 'file'))

            mainrec_key = struct.pack('>L', path2wrap[path[:-1]].cnid) + pstrname

            if isinstance(obj, File):
                drFilCnt += 1

                cdrType = 2
                # File thread records are optional on HFS volumes. We do not
                # emit them below, so leave kHFSThreadExistsMask clear.
                filFlags = int(bool(obj.locked))
                filTyp = 0
                filUsrWds = struct.pack('>4s4sHhhxxxxxx', wrap.type, wrap.creator, obj.flags, obj.y, obj.x)
                filFlNum = wrap.cnid
                # The start-block fields are obsolete and reserved; actual
                # fork locations are stored in filExtRec and filRExtRec.
                filStBlk, filLgLen, filPyLen = 0, len(wrap.data), bitmanip.pad_up(len(wrap.data), drAlBlkSiz)
                filRStBlk, filRLgLen, filRPyLen = 0, len(wrap.rsrc), bitmanip.pad_up(len(wrap.rsrc), drAlBlkSiz)
                filCrDat, filMdDat, filBkDat = obj.crdate, obj.mddate, obj.bkdate
                filFndrInfo = obj.fndrInfo or bytes(16)
                filClpSize = 0 # todo must fix
                filExtRec = struct.pack('>HHHHHH', *wrap.dfrk, 0, 0, 0, 0)
                filRExtRec = struct.pack('>HHHHHH', *wrap.rfrk, 0, 0, 0, 0)

                mainrec_val = struct.pack('>BxBB16sLHLLHLLLLL16sH12s12sxxxx',
                    cdrType, \
                    filFlags, filTyp, filUsrWds, filFlNum, \
                    filStBlk, filLgLen, filPyLen, \
                    filRStBlk, filRLgLen, filRPyLen, \
                    filCrDat, filMdDat, filBkDat, \
                    filFndrInfo, filClpSize, \
                    filExtRec, filRExtRec, \
                )

            else: # assume directory
                drDirCnt += 1

                cdrType = 1
                dirFlags = obj.flags # must fix
                dirVal = len(contents) if obj is self else len(obj)
                dirDirID = wrap.cnid
                dirCrDat, dirMdDat, dirBkDat = obj.crdate, obj.mddate, obj.bkdate
                dirUsrInfo = obj.usrInfo or bytes(16)
                dirFndrInfo = obj.fndrInfo or bytes(16)
                mainrec_val = struct.pack('>BxHHLLLL16s16sxxxxxxxxxxxxxxxx',
                    cdrType, dirFlags, dirVal, dirDirID,
                    dirCrDat, dirMdDat, dirBkDat,
                    dirUsrInfo, dirFndrInfo,
                )

            catalog.append((mainrec_key, mainrec_val))

            # File thread records appear to be buggy, but including them is not
            # actually required.
            if not isinstance(wrap.of, File):
                # The root directory appears to have an extra reserved byte in its key
                thdrec_key = struct.pack('>Lxx' if wrap.cnid == 2 else '>Lx', wrap.cnid)
                thdrec_val_type = 4 if isinstance(wrap.of, File) else 3
                thdrec_val = struct.pack('>BxxxxxxxxxL', thdrec_val_type, path2wrap[path[:-1]].cnid) + pstrname.ljust(31, b"\x00")

                catalog.append((thdrec_key, thdrec_val))


        # now it is time to sort these records! fuck that shit...
        catalog.sort(key=_catalog_rec_sort)
        catalogfile = btree.make_btree(catalog, bthKeyLen=37, blksize=drAlBlkSiz)
        # also need to do some cleverness to ensure that this gets picked up...
        drCTFlSize = len(catalogfile)
        drCTExtRec_Start = len(blkaccum)
        accumulate(bitmanip.chunkify(catalogfile, drAlBlkSiz))
        drCTExtRec_Cnt = len(blkaccum) - drCTExtRec_Start

        if len(blkaccum) > drNmAlBlks:
            raise ValueError('Does not fit!')

        # Create the bitmap of free volume allocation blocks
        bitmap = bitmanip.bits(bitmap_blk_cnt * 512 * 8, len(blkaccum))

        # Set the startup app
        if system_folder_cnid and startapp_folder_cnid:
            try:
                bootblocks[0x5A:0x6A] = _bb_name(startapp[-1])
            except:
                startapp_folder_cnid = 0

        # Create the Volume Information Block
        drNmFls = sum(isinstance(x, File) for x in contents.values())
        drNmRtDirs = sum(not isinstance(x, File) for x in contents.values())
        drVBMSt = 3 # first block of volume bitmap
        drAllocPtr = 0
        drClpSiz = drXTClpSiz = drCTClpSiz = drAlBlkSiz
        drAlBlSt = 3 + bitmap_blk_cnt
        drFreeBks = drNmAlBlks - len(blkaccum)
        drWrCnt = 0 # ????volume write count
        drVCSize = drVBMCSize = drCtlCSize = 0
        drVolBkUp = self.bkdate        # date and time of last backup
        drVSeqNum = 0                  # volume backup sequence number

        if self.open_folder is None:
            open_folder_cnid = 0
        else:
            try:
                open_folder_cnid = next(
                    wrap.cnid for wrap in path2wrap.values()
                    if wrap.of is self.open_folder and isinstance(wrap.of, AbstractFolder)
                )
            except StopIteration:
                raise ValueError('open_folder must be a folder in this volume')

        drFndrInfo = struct.pack(
            '>LLL20x',
            system_folder_cnid,
            startapp_folder_cnid,
            open_folder_cnid,
        )

        vib = struct.pack('>2sLLHHHHHLLHLH28pLHLLLHLL32sHHHLHHxxxxxxxxLHHxxxxxxxx',
            drSigWord, drCrDate, drLsMod, drAtrb, drNmFls,
            drVBMSt, drAllocPtr, drNmAlBlks, drAlBlkSiz, drClpSiz, drAlBlSt,
            drNxtCNID, drFreeBks, drVN, drVolBkUp, drVSeqNum,
            drWrCnt, drXTClpSiz, drCTClpSiz, drNmRtDirs, drFilCnt, drDirCnt,
            drFndrInfo, drVCSize, drVBMCSize, drCtlCSize,
            drXTFlSize, drXTExtRec_Start, drXTExtRec_Cnt,
            drCTFlSize, drCTExtRec_Start, drCTExtRec_Cnt,
        )
        vib += bytes(512-len(vib))

        assert all(len(x) == drAlBlkSiz for x in blkaccum)
        left_elements = [bootblocks, vib, bitmap, *blkaccum]

        unused_offset = sum(len(x) for x in left_elements)
        unused_length = size - unused_offset - 2*512

        right_elements = [vib, bytes(512)]

        if sparse:
            return b''.join(left_elements), unused_length, b''.join(right_elements)
        else:
            all_elements = left_elements
            all_elements.append(bytes(unused_length))
            all_elements.extend(right_elements)
            return b''.join(all_elements)
